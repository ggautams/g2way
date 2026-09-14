//! End-to-end tests for the M8+ streaming passthroughs: `Connection:
//! Upgrade` tunneling (WebSocket-style) and server-sent-event streaming
//! through a real g2way server.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use g2_core::ApiDefinition;
use g2_proxy::{Forwarder, Gateway, RouteTable};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

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

/// A keyless definition: these tests exercise proxying, not auth.
fn api(listen_path: &str, target: &str) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"stream","name":"stream","listen_path":"{listen_path}","target_url":"{target}","auth":{{"mode":"keyless"}}}}"#
    ))
    .expect("definition")
}

/// Spawns an upgrade-capable upstream: upgrade requests get a `101` and the
/// upgraded connection echoes every byte back; plain requests get a `200`
/// whose body reports whether an `Upgrade` header arrived.
async fn spawn_echo_upgrade_upstream() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|mut req: Request<Incoming>| async move {
                    if req.headers().contains_key("upgrade") {
                        let on_upgrade = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            let Ok(upgraded) = on_upgrade.await else {
                                return;
                            };
                            let mut io = TokioIo::new(upgraded);
                            let mut buf = [0u8; 1024];
                            while let Ok(n) = io.read(&mut buf).await {
                                if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        });
                        let resp = Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header("connection", "upgrade")
                            .header("upgrade", "echoproto")
                            .body(Empty::<Bytes>::new().boxed())
                            .expect("101 response");
                        Ok::<_, Infallible>(resp)
                    } else {
                        let resp = Response::new(
                            Full::new(Bytes::from_static(b"plain: no upgrade header")).boxed(),
                        );
                        Ok(resp)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    addr
}

/// Performs a raw HTTP/1.1 upgrade handshake against `gw` and returns the
/// stream (positioned just past the response head) plus the response head.
async fn raw_upgrade_handshake(gw: SocketAddr, path: &str) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(gw).await.expect("connect");
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nhost: gateway\r\n\
                 connection: upgrade\r\nupgrade: echoproto\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send handshake");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_ne!(
            stream.read(&mut byte).await.expect("read head"),
            0,
            "connection closed mid-head: {}",
            String::from_utf8_lossy(&head)
        );
        head.push(byte[0]);
    }
    (stream, String::from_utf8(head).expect("utf8 head"))
}

#[tokio::test]
async fn websocket_style_upgrade_tunnels_end_to_end() {
    let upstream = spawn_echo_upgrade_upstream().await;
    let mut def = api("/ws/", &format!("http://{upstream}"));
    def.enable_upgrades = true;
    def.validate().expect("valid definition");
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    let (mut stream, head) = raw_upgrade_handshake(gw, "/ws/chat").await;
    assert!(head.starts_with("HTTP/1.1 101"), "head: {head}");
    let head_lower = head.to_ascii_lowercase();
    assert!(head_lower.contains("upgrade: echoproto"), "head: {head}");
    assert!(head_lower.contains("connection: upgrade"), "head: {head}");

    // The tunnel is transparent in both directions, across multiple writes.
    for msg in [&b"ping-one"[..], &b"second message"[..]] {
        stream.write_all(msg).await.expect("send");
        let mut echoed = vec![0u8; msg.len()];
        stream.read_exact(&mut echoed).await.expect("echo");
        assert_eq!(echoed, msg);
    }

    // Closing our side tears the tunnel down; the upstream echo loop ends
    // and the gateway closes the client connection rather than leaking it.
    stream.shutdown().await.expect("close write half");
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.expect("drained");
    assert!(rest.is_empty(), "unexpected trailing bytes: {rest:?}");
}

#[tokio::test]
async fn upgrade_without_opt_in_downgrades_to_plain_http() {
    let upstream = spawn_echo_upgrade_upstream().await;
    // `enable_upgrades` left at its default (off): the upgrade headers are
    // hop-by-hop-stripped, so the upstream sees a plain GET and answers 200.
    let def = api("/plain/", &format!("http://{upstream}"));
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    let (mut stream, head) = raw_upgrade_handshake(gw, "/plain/chat").await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    let mut body = vec![0u8; b"plain: no upgrade header".len()];
    stream.read_exact(&mut body).await.expect("body");
    assert_eq!(&body[..], b"plain: no upgrade header");
}

#[tokio::test]
async fn sse_stream_outlives_the_upstream_timeout() {
    // The upstream sends one event immediately, then holds the second until
    // the test signals — so receiving event one while the sender is parked
    // proves the gateway streams frames instead of buffering the body, with
    // no timing dependence.
    let release = Arc::new(Mutex::new(None::<oneshot::Sender<()>>));
    let release_upstream = Arc::clone(&release);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let upstream = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let release = Arc::clone(&release_upstream);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let (tx, rx) = oneshot::channel::<()>();
                    *release.lock().expect("release slot") = Some(tx);
                    async move {
                        let events = futures_util::stream::unfold(
                            (0u8, Some(rx)),
                            |(step, rx)| async move {
                                match step {
                                    0 => Some((
                                        Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                                            b"data: one\n\n",
                                        ))),
                                        (1, rx),
                                    )),
                                    1 => {
                                        let _ = rx.expect("receiver at step 1").await;
                                        Some((
                                            Ok(Frame::data(Bytes::from_static(b"data: two\n\n"))),
                                            (2, None),
                                        ))
                                    }
                                    _ => None,
                                }
                            },
                        );
                        let mut resp = Response::new(StreamBody::new(events));
                        resp.headers_mut().insert(
                            "content-type",
                            http::HeaderValue::from_static("text/event-stream"),
                        );
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    // A 250ms upstream timeout: it must only bound the wait for response
    // *headers*, never cut an in-flight stream.
    let mut def = api("/sse/", &format!("http://{upstream}"));
    def.upstream_timeout_ms = 250;
    def.validate().expect("valid definition");
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(format!("http://{gw}/sse/feed").parse().expect("url"))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();

    // Event one arrives while the upstream still holds event two.
    let first = body
        .frame()
        .await
        .expect("first frame")
        .expect("frame ok")
        .into_data()
        .expect("data frame");
    assert_eq!(&first[..], b"data: one\n\n");

    // Wait past the upstream timeout, then release event two: an intact
    // stream proves the timeout covered only the headers.
    tokio::time::sleep(Duration::from_millis(400)).await;
    release
        .lock()
        .expect("release slot")
        .take()
        .expect("upstream registered the release sender")
        .send(())
        .expect("upstream body still listening");

    let mut rest = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.expect("frame ok").into_data() {
            rest.extend_from_slice(&data);
        }
    }
    assert_eq!(&rest[..], b"data: two\n\n");
}
