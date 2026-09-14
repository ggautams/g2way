//! End-to-end body-transform tests: a real g2way server rewriting request
//! and response bodies with minijinja templates in front of an echo
//! upstream over TCP (milestone M8+, ADR-0007).

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

/// Spawns an echo upstream: every request is answered with a JSON envelope
/// describing what the upstream received (method, path, body and content
/// type), so tests can assert on exactly what was forwarded.
async fn spawn_echo_upstream() -> SocketAddr {
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
                    let content_type = req
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
                    let body = req.collect().await.expect("body").to_bytes();
                    let reply = serde_json::json!({
                        "saw": {
                            "method": method,
                            "path": path,
                            "content_type": content_type,
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

/// A keyless API with one request rule (wrap `/wrap` POSTs), one response
/// rule (reshape `/reshape` responses), and a tiny request-body cap on
/// `/wrap` traffic via `max_request_body_bytes`.
fn transform_api(target: &str) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(
        &serde_json::json!({
            "api_id": "bt-e2e",
            "name": "bt-e2e",
            "listen_path": "/t/",
            "target_url": target,
            "auth": { "mode": "keyless" },
            "max_request_body_bytes": 256,
            "transform_body": {
                "request": [{
                    "pattern": "^/t/wrap$",
                    "methods": ["POST"],
                    "template": "{\"wrapped\": {{ body | tojson }}, \"via\": \"{{ _g2.method }} {{ _g2.path }}\"}"
                }],
                "response": [{
                    "pattern": "^/t/reshape$",
                    "template": "{\"upstream_said\": {{ body.saw.body | tojson }}, \"status\": {{ _g2.status }}}"
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

#[tokio::test]
async fn request_bodies_are_rewritten_before_forwarding() {
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![transform_api(&format!("http://{upstream}"))]).await;

    let (status, body) = send(gw, Method::POST, "/t/wrap", r#"{"id": 7}"#).await;
    assert_eq!(status, StatusCode::OK, "got body: {body}");
    let reply: serde_json::Value = serde_json::from_str(&body).expect("upstream JSON");
    let forwarded: serde_json::Value =
        serde_json::from_str(reply["saw"]["body"].as_str().expect("body string"))
            .expect("forwarded body is JSON");
    assert_eq!(forwarded["wrapped"]["id"], 7);
    assert_eq!(forwarded["via"], "POST /t/wrap");
    assert_eq!(reply["saw"]["content_type"], "application/json");
}

#[tokio::test]
async fn response_bodies_are_rewritten_before_the_client() {
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![transform_api(&format!("http://{upstream}"))]).await;

    let (status, body) = send(gw, Method::POST, "/t/reshape", "ping").await;
    assert_eq!(status, StatusCode::OK, "got body: {body}");
    let reply: serde_json::Value = serde_json::from_str(&body).expect("client JSON");
    assert_eq!(reply["upstream_said"], "ping");
    assert_eq!(reply["status"], 200);
}

#[tokio::test]
async fn non_matching_paths_stream_through_byte_identical() {
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![transform_api(&format!("http://{upstream}"))]).await;

    let (status, body) = send(gw, Method::POST, "/t/other", "untouched payload").await;
    assert_eq!(status, StatusCode::OK);
    let reply: serde_json::Value = serde_json::from_str(&body).expect("upstream JSON");
    assert_eq!(reply["saw"]["body"], "untouched payload");
    assert_eq!(
        reply["saw"]["content_type"],
        serde_json::Value::Null,
        "no content type invented for untouched traffic"
    );
}

#[tokio::test]
async fn oversized_request_bodies_are_rejected_with_413() {
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![transform_api(&format!("http://{upstream}"))]).await;

    let big = "x".repeat(512);
    let (status, body) = send(gw, Method::POST, "/t/wrap", &big).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "got body: {body}");
}
