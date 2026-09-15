//! End-to-end GraphQL schema-sync test: a real g2way server whose schema
//! follows the upstream's introspection answer live (milestone M9,
//! ADR-0008) — no reload, no restart.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
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

/// Introspection JSON for `type Query { hello: String extra: Int }` — the
/// grown schema the upstream reveals after its "deploy".
const GROWN_INTROSPECTION: &str = r#"{"data":{"__schema":{
    "queryType":{"name":"Query"},
    "types":[
        {"kind":"OBJECT","name":"Query","fields":[
            {"name":"hello","args":[],"type":{"kind":"SCALAR","name":"String"}},
            {"name":"extra","args":[],"type":{"kind":"SCALAR","name":"Int"}}]},
        {"kind":"SCALAR","name":"String"},
        {"kind":"SCALAR","name":"Int"}
    ]}}}"#;

/// Spawns a fake GraphQL upstream. Introspection requests (body naming
/// `__schema`) get whatever the returned handle currently holds; every
/// other request is echoed back like `graphql_e2e`'s upstream.
async fn spawn_switchable_upstream() -> (SocketAddr, Arc<Mutex<(StatusCode, String)>>) {
    // Introspection starts broken: the upstream refuses it, so the gateway
    // must keep serving its seed schema.
    let introspection = Arc::new(Mutex::new((
        StatusCode::OK,
        r#"{"errors":[{"message":"introspection is not allowed"}]}"#.to_owned(),
    )));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    let served = Arc::clone(&introspection);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let served = Arc::clone(&served);
                    async move {
                        let body = req.collect().await.expect("body").to_bytes();
                        let text = String::from_utf8_lossy(&body);
                        let (status, reply) = if text.contains("__schema") {
                            served.lock().expect("not poisoned").clone()
                        } else {
                            (
                                StatusCode::OK,
                                serde_json::json!({
                                    "data": { "hello": "world" },
                                    "saw": { "body": text }
                                })
                                .to_string(),
                            )
                        };
                        let mut resp = Response::new(Full::new(Bytes::from(reply)));
                        *resp.status_mut() = status;
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, introspection)
}

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

async fn post_query(gw: SocketAddr, query: &str) -> (StatusCode, String) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{gw}/gql/"))
        .body(Full::new(Bytes::from(
            serde_json::json!({ "query": query }).to_string(),
        )))
        .expect("request");
    let resp = client.request(req).await.expect("response");
    let status = resp.status();
    let body = resp.collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn schema_follows_upstream_introspection_live() {
    let (upstream, introspection) = spawn_switchable_upstream().await;
    let def: ApiDefinition = serde_json::from_str(
        &serde_json::json!({
            "api_id": "gql-sync-e2e",
            "name": "gql-sync-e2e",
            "listen_path": "/gql/",
            "target_url": format!("http://{upstream}"),
            "auth": { "mode": "keyless" },
            "graphql": {
                "schema": "type Query { hello: String }",
                "schema_sync": { "interval_ms": 50, "timeout_ms": 1000 }
            }
        })
        .to_string(),
    )
    .expect("definition");
    let (gw, _shutdown) = spawn_gateway(vec![def]).await;

    // Introspection is refused upstream: the seed schema serves. Known
    // fields pass, unknown fields are rejected by validation.
    let (status, body) = post_query(gw, "{ hello }").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("\"hello\""), "body: {body}");
    let (status, body) = post_query(gw, "{ extra }").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(body.contains("errors"), "body: {body}");

    // The upstream "deploys" a grown schema and starts answering
    // introspection: within a few 50ms sync ticks, `extra` validates and
    // forwards — no reload, no restart.
    *introspection.lock().expect("lock") = (StatusCode::OK, GROWN_INTROSPECTION.to_owned());
    let mut synced = false;
    for _ in 0..200 {
        let (status, body) = post_query(gw, "{ extra }").await;
        if status == StatusCode::OK {
            assert!(
                body.contains("\"saw\""),
                "the accepted query must reach the upstream, body: {body}"
            );
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        synced,
        "`{{ extra }}` never validated after the schema grew"
    );

    // The seed's fields keep working against the synced schema.
    let (status, body) = post_query(gw, "{ hello }").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}
