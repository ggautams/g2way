//! End-to-end GraphQL tests: a real g2way server policing GraphQL traffic
//! in front of a fake GraphQL upstream over TCP (milestone M9).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use g2_core::ApiDefinition;
use g2_proxy::{Forwarder, Gateway, RouteResources, RouteTable};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Spawns a fake GraphQL upstream: every request is answered with a JSON
/// envelope describing what the upstream received (method, path, and the
/// raw body), so tests can assert on exactly what was forwarded.
async fn spawn_graphql_upstream() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(|req: Request<Incoming>| async move {
                    let method = req.method().to_string();
                    let path = req.uri().to_string();
                    let body = req.collect().await.expect("body").to_bytes();
                    let reply = serde_json::json!({
                        "data": { "hello": "world" },
                        "saw": {
                            "method": method,
                            "path": path,
                            "body": String::from_utf8_lossy(&body),
                        }
                    })
                    .to_string();
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(reply))))
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

/// A keyless GraphQL API definition with a depth limit, playground, and
/// one persisted GraphQL-as-REST endpoint.
fn graphql_api(target: &str) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(
        &serde_json::json!({
            "api_id": "gql-e2e",
            "name": "gql-e2e",
            "listen_path": "/gql/",
            "target_url": target,
            "auth": { "mode": "keyless" },
            "graphql": {
                "schema": "type Query { hello: String user(id: ID!): User } \
                           type User { id: ID! name: String friend: User }",
                "max_query_depth": 3,
                "playground": {},
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
) -> (StatusCode, String) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method(method)
        .uri(format!("http://{gw}{path_and_query}"))
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("request");
    let resp = client.request(req).await.expect("response");
    let status = resp.status();
    let body = resp.collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn post_query(gw: SocketAddr, query: &str) -> (StatusCode, String) {
    let body = serde_json::json!({ "query": query }).to_string();
    send(gw, Method::POST, "/gql", &body).await
}

#[tokio::test]
async fn valid_queries_are_forwarded_byte_for_byte() {
    let upstream = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![graphql_api(&format!("http://{upstream}"))]).await;

    let raw = r#"{"query":"{ hello }","variables":{"x":1}}"#;
    let (status, body) = send(gw, Method::POST, "/gql", raw).await;
    assert_eq!(status, StatusCode::OK, "got body: {body}");
    let reply: serde_json::Value = serde_json::from_str(&body).expect("upstream JSON");
    assert_eq!(reply["saw"]["method"], "POST");
    assert_eq!(reply["saw"]["body"], raw, "upstream saw the exact bytes");
}

#[tokio::test]
async fn invalid_and_deep_queries_never_reach_the_upstream() {
    let upstream = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![graphql_api(&format!("http://{upstream}"))]).await;

    // A field the schema does not define: 400 with GraphQL-style errors.
    let (status, body) = post_query(gw, "{ nonexistent }").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("errors"), "got: {body}");

    // Depth 4 against a limit of 3: 403.
    let (status, body) = post_query(gw, "{ user(id: \"1\") { friend { friend { name } } } }").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, r#"{"error":"depth limit exceeded"}"#);

    // At the limit: forwarded.
    let (status, _) = post_query(gw, "{ user(id: \"1\") { friend { name } } }").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn playground_is_served_by_the_gateway() {
    let upstream = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![graphql_api(&format!("http://{upstream}"))]).await;

    let (status, body) = send(gw, Method::GET, "/gql/playground", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("GraphiQL"), "got: {body}");
    assert!(body.contains("url: '/gql'"), "endpoint substituted: {body}");
}

#[tokio::test]
async fn persisted_rest_endpoint_builds_the_graphql_request() {
    let upstream = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![graphql_api(&format!("http://{upstream}"))]).await;

    let (status, body) = send(gw, Method::GET, "/gql/users/42", "").await;
    assert_eq!(status, StatusCode::OK, "got body: {body}");
    let reply: serde_json::Value = serde_json::from_str(&body).expect("upstream JSON");
    assert_eq!(reply["saw"]["method"], "POST", "rewritten to a POST");
    let upstream_body: serde_json::Value =
        serde_json::from_str(reply["saw"]["body"].as_str().expect("body string"))
            .expect("forwarded GraphQL envelope");
    assert_eq!(upstream_body["variables"]["id"], "42");
    assert!(upstream_body["query"]
        .as_str()
        .expect("query")
        .contains("user(id: $id)"));
}

#[tokio::test]
async fn graphql_over_get_works_end_to_end() {
    let upstream = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![graphql_api(&format!("http://{upstream}"))]).await;

    let (status, _) = send(gw, Method::GET, "/gql?query=%7B%20hello%20%7D", "").await;
    assert_eq!(status, StatusCode::OK);

    // Introspection is enabled by default and passes the depth limit.
    let (status, _) = send(
        gw,
        Method::GET,
        "/gql?query=%7B%20__schema%20%7B%20queryType%20%7B%20name%20%7D%20%7D%20%7D",
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn disabled_introspection_is_rejected_at_the_gateway() {
    let upstream = spawn_graphql_upstream().await;
    let mut def = graphql_api(&format!("http://{upstream}"));
    def.graphql.as_mut().expect("set").introspection_enabled = false;
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    let (status, body) = post_query(gw, "{ __schema { queryType { name } } }").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, r#"{"error":"introspection is disabled"}"#);
}

#[tokio::test]
async fn non_graphql_apis_are_untouched() {
    let upstream = spawn_graphql_upstream().await;
    let plain: ApiDefinition = serde_json::from_str(
        &serde_json::json!({
            "api_id": "plain",
            "name": "plain",
            "listen_path": "/plain/",
            "target_url": format!("http://{upstream}"),
            "auth": { "mode": "keyless" }
        })
        .to_string(),
    )
    .expect("definition");
    let (gw, _stop) = spawn_gateway(vec![plain]).await;

    // Any body proxies straight through — no GraphQL parsing at all.
    let (status, body) = send(gw, Method::POST, "/plain/x", "not graphql").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("not graphql"), "got: {body}");
}
