//! End-to-end gRPC-passthrough tests: an HTTP/2 client speaking h2c to a
//! real g2way server, proxied to an HTTP/2-only (h2c prior knowledge)
//! upstream answering gRPC-shaped responses — data frame plus a
//! `grpc-status` trailer that must reach the client as a trailer.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use g2_core::ApiDefinition;
use g2_proxy::{Forwarder, Gateway, RouteTable};
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// The gRPC-shaped upstream response body: one data frame, then trailers.
type GrpcBody = StreamBody<
    futures_util::stream::Iter<std::vec::IntoIter<Result<Frame<Bytes>, std::convert::Infallible>>>,
>;

/// Echoes the request's protocol version, `te` header, and body length into
/// response headers, and answers `content-type: application/grpc` with a
/// data frame followed by a `grpc-status: 0` trailer frame.
async fn grpc_style_service(
    req: Request<Incoming>,
) -> Result<Response<GrpcBody>, std::convert::Infallible> {
    let version = format!("{:?}", req.version());
    let te = req
        .headers()
        .get("te")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<none>")
        .to_owned();
    let len = req.collect().await.expect("body").to_bytes().len();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    let frames = vec![
        Ok(Frame::data(Bytes::from_static(b"grpc reply"))),
        Ok(Frame::trailers(trailers)),
    ];
    Ok(Response::builder()
        .header("content-type", "application/grpc")
        .header("x-seen-version", version)
        .header("x-seen-te", te)
        .header("x-seen-len", len.to_string())
        .body(StreamBody::new(futures_util::stream::iter(frames)))
        .expect("response"))
}

/// Serves [`grpc_style_service`] over plaintext HTTP/2 only (h2c prior
/// knowledge — an HTTP/1.1 request fails the connection).
async fn spawn_h2c_upstream() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service_fn(grpc_style_service))
                    .await;
            });
        }
    });
    addr
}

/// Serves [`grpc_style_service`] over plain HTTP/1.1.
async fn spawn_h1_upstream() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(grpc_style_service))
                    .await;
            });
        }
    });
    addr
}

/// Starts a full g2way server for `defs`; returns its address and a shutdown
/// trigger.
async fn spawn_gateway(defs: Vec<ApiDefinition>) -> (SocketAddr, oneshot::Sender<()>) {
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let table = RouteTable::build(defs, &Forwarder::new(), &storage, None, None, None, None)
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

/// A keyless definition; `upstream_http2` set per test.
fn api(listen_path: &str, target: &str, upstream_http2: bool) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"grpc-e2e","name":"grpc-e2e","listen_path":"{listen_path}",
            "target_url":"{target}","auth":{{"mode":"keyless"}},
            "upstream_http2":{upstream_http2}}}"#
    ))
    .expect("definition")
}

/// An HTTP/2 prior-knowledge client, the way a real gRPC client dials the
/// gateway's plaintext listener.
fn h2c_client() -> Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http()
}

/// A gRPC-shaped POST: `application/grpc`, `te: trailers`, a message body.
fn grpc_request(gw: SocketAddr, path: &str) -> Request<Full<Bytes>> {
    Request::post(format!("http://{gw}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from_static(b"\0\0\0\0\x05hello")))
        .expect("request")
}

#[tokio::test]
async fn grpc_style_call_end_to_end_over_h2c() {
    let upstream = spawn_h2c_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![api("/grpc/", &format!("http://{upstream}"), true)]).await;

    let resp = h2c_client()
        .request(grpc_request(gw, "/grpc/echo.Echo/Say"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "application/grpc");
    // The upstream leg really was HTTP/2 with `te: trailers` intact, and
    // the request body arrived whole.
    assert_eq!(resp.headers()["x-seen-version"], "HTTP/2.0");
    assert_eq!(resp.headers()["x-seen-te"], "trailers");
    assert_eq!(resp.headers()["x-seen-len"], "10");

    let collected = resp.into_body().collect().await.expect("body");
    let trailers = collected
        .trailers()
        .cloned()
        .expect("grpc-status trailer must reach the client as a trailer");
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(&collected.to_bytes()[..], b"grpc reply");
}

#[tokio::test]
async fn upstream_http2_off_forwards_http11() {
    let upstream = spawn_h1_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![api("/h1/", &format!("http://{upstream}"), false)]).await;

    // The client-facing leg is HTTP/2 either way (the listener sniffs the
    // h2c preface); without the flag the upstream leg stays HTTP/1.1 and
    // `te` stays stripped like any hop-by-hop header.
    let resp = h2c_client()
        .request(grpc_request(gw, "/h1/echo.Echo/Say"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-seen-version"], "HTTP/1.1");
    assert_eq!(resp.headers()["x-seen-te"], "<none>");
}

#[tokio::test]
async fn versioned_api_mixes_h1_and_h2_upstreams() {
    let h1_upstream = spawn_h1_upstream().await;
    let h2_upstream = spawn_h2c_upstream().await;

    // The base (default) version proxies HTTP/1.1; v2 overrides both the
    // target and the protocol. Each version gets its own upstream target,
    // so the two clients coexist on one API.
    let mut def = api("/mix/", &format!("http://{h1_upstream}"), false);
    def.versioning = Some(
        serde_json::from_str(&format!(
            r#"{{
                "default_version": "v1",
                "versions": {{
                    "v1": {{}},
                    "v2": {{"target_url": "http://{h2_upstream}", "upstream_http2": true}}
                }}
            }}"#
        ))
        .expect("versioning JSON"),
    );
    def.validate().expect("valid definition");
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    let call = |version: &'static str| async move {
        let mut req = grpc_request(gw, "/mix/echo.Echo/Say");
        req.headers_mut()
            .insert("x-api-version", HeaderValue::from_static(version));
        h2c_client().request(req).await.expect("response")
    };

    let resp = call("v1").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-seen-version"], "HTTP/1.1");

    let resp = call("v2").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-seen-version"], "HTTP/2.0");
    let trailers = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .trailers()
        .cloned()
        .expect("trailers forwarded on the h2 version");
    assert_eq!(trailers["grpc-status"], "0");
}
