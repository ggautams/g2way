//! End-to-end GraphQL-aware response caching (milestone M9, ADR-0012): a
//! real g2way server in front of a counting fake upstream proves repeat
//! queries are answered from the cache, while mutations, distinct
//! variables, and error responses keep reaching the upstream.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use g2_core::ApiDefinition;
use g2_proxy::{Forwarder, Gateway, RouteResources, RouteTable};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Spawns a counting fake GraphQL upstream. Requests whose body mentions
/// `boom` are answered with a GraphQL `errors` envelope (still `200`);
/// everything else gets a success envelope echoing the request body, so
/// distinct requests produce distinct cacheable payloads.
async fn spawn_counting_upstream(count: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let count = Arc::clone(&count);
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        let body = req.collect().await.expect("body").to_bytes();
                        let text = String::from_utf8_lossy(&body);
                        let reply = if text.contains("boom") {
                            serde_json::json!({
                                "data": null,
                                "errors": [{ "message": "boom" }]
                            })
                        } else {
                            serde_json::json!({ "data": { "echo": text } })
                        }
                        .to_string();
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            reply,
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

/// Starts a full g2way server for `defs`; returns its address and a
/// shutdown trigger.
async fn spawn_gateway(defs: Vec<ApiDefinition>) -> (SocketAddr, oneshot::Sender<()>) {
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let table = RouteTable::build(defs, &RouteResources::new(&Forwarder::new(), &storage))
        .expect("route table");
    let gateway = Arc::new(Gateway::new(table));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        g2way::server::serve(
            listener,
            gateway,
            async {
                let _ = rx.await;
            },
            Duration::from_secs(5),
        )
        .await
        .expect("serve");
    });
    (addr, tx)
}

/// A keyless GraphQL API with `graphql.cache` enabled and one persisted
/// endpoint.
fn cached_graphql_api(target: &str) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(
        &serde_json::json!({
            "api_id": "gql-cache-e2e",
            "name": "gql-cache-e2e",
            "listen_path": "/gql/",
            "target_url": target,
            "auth": { "mode": "keyless" },
            "graphql": {
                "schema": "type Query { hello: String boom: String user(id: ID!): User } \
                           type Mutation { rename(id: ID!, name: String!): User } \
                           type User { id: ID! name: String }",
                "cache": {},
                "persisted_queries": [{
                    "method": "GET",
                    "path": "/users/{id}",
                    "operation": "query User($id: ID!) { user(id: $id) { name } }",
                    "variables": { "id": "$path.id" }
                }]
            }
        })
        .to_string(),
    )
    .expect("definition")
}

async fn send(
    gw: SocketAddr,
    method: Method,
    path_and_query: &str,
    body: &str,
) -> (StatusCode, HeaderMap, String) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method(method)
        .uri(format!("http://{gw}{path_and_query}"))
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("request");
    let resp = client.request(req).await.expect("response");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.collect().await.expect("body").to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

async fn post_envelope(
    gw: SocketAddr,
    envelope: serde_json::Value,
) -> (StatusCode, HeaderMap, String) {
    send(gw, Method::POST, "/gql", &envelope.to_string()).await
}

/// Waits until `count` stops changing for a moment — used only for
/// negative assertions after the response has fully arrived.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(30)).await;
}

#[tokio::test]
async fn repeat_queries_are_served_from_the_cache() {
    let count = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_counting_upstream(Arc::clone(&count)).await;
    let (gw, _stop) = spawn_gateway(vec![cached_graphql_api(&format!("http://{upstream}"))]).await;

    let envelope = serde_json::json!({ "query": "{ hello }" });
    let (status, headers, first) = post_envelope(gw, envelope.clone()).await;
    assert_eq!(status, StatusCode::OK, "got: {first}");
    assert!(!headers.contains_key("x-g2-cache"), "first request misses");

    // Bounded wait for the background cache write, proven by the hit.
    let mut hit = None;
    for _ in 0..100 {
        let (status, headers, body) = post_envelope(gw, envelope.clone()).await;
        assert_eq!(status, StatusCode::OK);
        if headers.get("x-g2-cache").is_some_and(|v| v == "hit") {
            hit = Some(body);
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let hit = hit.expect("a cache hit within the deadline");
    assert_eq!(hit, first, "the hit replays the stored body");
    let upstream_hits = count.load(Ordering::SeqCst);

    let (_, headers, body) = post_envelope(gw, envelope).await;
    assert!(headers.get("x-g2-cache").is_some_and(|v| v == "hit"));
    assert_eq!(body, first);
    assert_eq!(
        count.load(Ordering::SeqCst),
        upstream_hits,
        "hits never reach the upstream"
    );
}

#[tokio::test]
async fn mutations_and_distinct_variables_always_forward() {
    let count = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_counting_upstream(Arc::clone(&count)).await;
    let (gw, _stop) = spawn_gateway(vec![cached_graphql_api(&format!("http://{upstream}"))]).await;

    // The same mutation twice: both reach the upstream, nothing is marked.
    let mutation =
        serde_json::json!({ "query": "mutation { rename(id: \"1\", name: \"x\") { id } }" });
    for _ in 0..2 {
        let (status, headers, body) = post_envelope(gw, mutation.clone()).await;
        assert_eq!(status, StatusCode::OK, "got: {body}");
        assert!(!headers.contains_key("x-g2-cache"));
    }
    assert_eq!(count.load(Ordering::SeqCst), 2, "mutations bypass");

    // The same query with different variables: distinct entries.
    let query = "query U($id: ID!) { user(id: $id) { name } }";
    let (status, _, body) = post_envelope(
        gw,
        serde_json::json!({ "query": query, "variables": { "id": "1" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    let (status, headers, body) = post_envelope(
        gw,
        serde_json::json!({ "query": query, "variables": { "id": "2" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert!(!headers.contains_key("x-g2-cache"));
    assert_eq!(count.load(Ordering::SeqCst), 4, "distinct variables miss");
}

#[tokio::test]
async fn error_responses_are_never_cached() {
    let count = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_counting_upstream(Arc::clone(&count)).await;
    let (gw, _stop) = spawn_gateway(vec![cached_graphql_api(&format!("http://{upstream}"))]).await;

    let envelope = serde_json::json!({ "query": "{ boom }" });
    for round in 1..=3 {
        let (status, headers, body) = post_envelope(gw, envelope.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("errors"), "got: {body}");
        assert!(!headers.contains_key("x-g2-cache"));
        settle().await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            round,
            "error responses always forward"
        );
    }
}

#[tokio::test]
async fn persisted_endpoints_are_cached_per_path_parameter() {
    let count = Arc::new(AtomicUsize::new(0));
    let upstream = spawn_counting_upstream(Arc::clone(&count)).await;
    let (gw, _stop) = spawn_gateway(vec![cached_graphql_api(&format!("http://{upstream}"))]).await;

    let (status, _, first) = send(gw, Method::GET, "/gql/users/1", "").await;
    assert_eq!(status, StatusCode::OK, "got: {first}");

    let mut hit = None;
    for _ in 0..100 {
        let (_, headers, body) = send(gw, Method::GET, "/gql/users/1", "").await;
        if headers.get("x-g2-cache").is_some_and(|v| v == "hit") {
            hit = Some(body);
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(hit.expect("a cache hit"), first);
    let after_same = count.load(Ordering::SeqCst);

    // A different path parameter is a different entry.
    let (status, headers, body) = send(gw, Method::GET, "/gql/users/2", "").await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert!(!headers.contains_key("x-g2-cache"));
    assert_eq!(count.load(Ordering::SeqCst), after_same + 1);
}
