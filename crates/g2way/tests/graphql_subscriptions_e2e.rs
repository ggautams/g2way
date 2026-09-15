//! End-to-end tests for M9 GraphQL subscriptions over WebSocket
//! (ADR-0009): real WebSocket sessions through a real g2way server, with a
//! graphql-ws-speaking fake upstream that logs every message it receives —
//! so tests can prove denied operations never crossed the gateway.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use g2_core::ApiDefinition;
use g2_proxy::{Forwarder, Gateway, RouteResources, RouteTable};
use http::{Response, StatusCode};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// Starts a full g2way server for `defs` over `storage`; returns its
/// address and a shutdown trigger.
async fn spawn_gateway(
    defs: Vec<ApiDefinition>,
    storage: g2_storage::SharedStorage,
) -> (SocketAddr, oneshot::Sender<()>) {
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

const SCHEMA: &str = "type Query { hello: String nested: Nested } \
                      type Nested { leaf: String } \
                      type Subscription { ticks: Int secret: String }";

/// A subscriptions-enabled GraphQL definition (keyless unless the test
/// tweaks `auth`).
fn subscriptions_api(target: &str, max_depth: Option<u32>) -> ApiDefinition {
    let def: ApiDefinition = serde_json::from_value(serde_json::json!({
        "api_id": "subs",
        "name": "subs",
        "listen_path": "/gql/",
        "target_url": target,
        "auth": { "mode": "keyless" },
        "graphql": {
            "schema": SCHEMA,
            "max_query_depth": max_depth,
            "subscriptions": {},
        },
    }))
    .expect("definition");
    def.validate().expect("valid definition");
    def
}

/// Spawns a graphql-ws upstream: WebSocket handshakes get a `101` (with
/// `echo_protocol` as the negotiated subprotocol, when set) and a scripted
/// server behind it — `connection_init` is answered with
/// `connection_ack`, any message carrying an `id` with a canned `next` for
/// that id. Every received text lands in the returned log.
async fn spawn_graphql_ws_upstream(
    echo_protocol: Option<&'static str>,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    let log = Arc::new(Mutex::new(Vec::new()));
    let task_log = Arc::clone(&log);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let log = Arc::clone(&task_log);
            tokio::spawn(async move {
                let service = service_fn(move |mut req: hyper::Request<Incoming>| {
                    let log = Arc::clone(&log);
                    async move {
                        let key = req
                            .headers()
                            .get("sec-websocket-key")
                            .expect("handshake carries a key")
                            .clone();
                        let on_upgrade = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            let Ok(upgraded) = on_upgrade.await else {
                                return;
                            };
                            let mut ws = WebSocketStream::from_raw_socket(
                                TokioIo::new(upgraded),
                                Role::Server,
                                None,
                            )
                            .await;
                            while let Some(Ok(msg)) = ws.next().await {
                                let Message::Text(text) = msg else {
                                    if msg.is_close() {
                                        break;
                                    }
                                    continue;
                                };
                                log.lock().expect("log").push(text.to_string());
                                let parsed: serde_json::Value =
                                    serde_json::from_str(text.as_str()).expect("client JSON");
                                let reply = if parsed["type"] == "connection_init" {
                                    serde_json::json!({ "type": "connection_ack" })
                                } else if let Some(id) = parsed.get("id") {
                                    serde_json::json!({
                                        "id": id,
                                        "type": "next",
                                        "payload": { "data": { "ticks": 1 } },
                                    })
                                } else {
                                    continue;
                                };
                                if ws.send(Message::text(reply.to_string())).await.is_err() {
                                    break;
                                }
                            }
                        });
                        let mut resp = Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header("connection", "upgrade")
                            .header("upgrade", "websocket")
                            .header("sec-websocket-accept", derive_accept_key(key.as_bytes()));
                        if let Some(protocol) = echo_protocol {
                            resp = resp.header("sec-websocket-protocol", protocol);
                        }
                        Ok::<_, std::convert::Infallible>(
                            resp.body(Empty::<bytes::Bytes>::new()).expect("101"),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    (addr, log)
}

/// Opens a WebSocket to the gateway with the given subprotocol offer (and
/// optional bearer token), returning the socket and the `101` response.
async fn connect(
    gw: SocketAddr,
    protocols: &str,
    bearer: Option<&str>,
) -> Result<
    (
        WebSocketStream<TcpStream>,
        tokio_tungstenite::tungstenite::handshake::client::Response,
    ),
    tokio_tungstenite::tungstenite::Error,
> {
    let mut request = format!("ws://{gw}/gql/")
        .into_client_request()
        .expect("client request");
    request.headers_mut().insert(
        "sec-websocket-protocol",
        protocols.parse().expect("protocol header"),
    );
    if let Some(token) = bearer {
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {token}").parse().expect("auth header"),
        );
    }
    let stream = TcpStream::connect(gw).await.expect("connect");
    tokio_tungstenite::client_async(request, stream).await
}

/// The next message on `ws`, with a test timeout.
async fn recv(ws: &mut WebSocketStream<TcpStream>) -> Message {
    tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timed out waiting for a message")
        .expect("stream ended")
        .expect("frame ok")
}

#[tokio::test]
async fn allowed_subscription_streams_end_to_end() {
    let (upstream, log) = spawn_graphql_ws_upstream(Some("graphql-transport-ws")).await;
    let def = subscriptions_api(&format!("http://{upstream}"), None);
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let (gw, _stop) = spawn_gateway(vec![def], storage).await;

    let (mut ws, resp) = connect(gw, "graphql-transport-ws", None)
        .await
        .expect("handshake succeeds");
    // The upstream's subprotocol pick crossed the gateway to the client
    // (like Sec-WebSocket-Accept, which tungstenite already verified).
    assert_eq!(
        resp.headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("graphql-transport-ws")
    );

    ws.send(Message::text(r#"{"type":"connection_init"}"#))
        .await
        .expect("send init");
    assert_eq!(
        recv(&mut ws).await,
        Message::text(r#"{"type":"connection_ack"}"#)
    );

    let subscribe = r#"{"id":"1","type":"subscribe","payload":{"query":"subscription { ticks }"}}"#;
    ws.send(Message::text(subscribe))
        .await
        .expect("send subscribe");
    let next = recv(&mut ws).await;
    let json: serde_json::Value =
        serde_json::from_str(next.to_text().expect("text")).expect("json");
    assert_eq!(json["type"], "next");
    assert_eq!(json["payload"]["data"]["ticks"], 1);

    // The upstream saw the original texts verbatim.
    let seen = log.lock().expect("log").clone();
    assert_eq!(
        seen,
        vec![
            r#"{"type":"connection_init"}"#.to_owned(),
            subscribe.to_owned()
        ]
    );

    ws.close(None).await.expect("close");
}

#[tokio::test]
async fn restricted_field_subscribe_never_reaches_the_upstream() {
    use g2_core::session::{hash_key, session_storage_key};

    let (upstream, log) = spawn_graphql_ws_upstream(Some("graphql-transport-ws")).await;
    // An auth-token API whose key blocks Subscription.secret.
    let mut def = subscriptions_api(&format!("http://{upstream}"), None);
    def.auth = serde_json::from_value(serde_json::json!({ "mode": "auth_token" })).expect("auth");
    def.validate().expect("valid definition");

    let session: g2_core::KeySession = serde_json::from_value(serde_json::json!({
        "access": {
            "subs": {
                "restricted_types": [ { "name": "Subscription", "fields": ["secret"] } ],
            },
        },
    }))
    .expect("session");
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    storage
        .set(
            &session_storage_key("default", &hash_key("ws-key")),
            &serde_json::to_string(&session).expect("json"),
            None,
        )
        .await
        .expect("seed key");
    let (gw, _stop) = spawn_gateway(vec![def], storage).await;

    // No credential: the auth chain rejects the handshake itself.
    let err = connect(gw, "graphql-transport-ws", None)
        .await
        .expect_err("handshake without a token is refused");
    let tokio_tungstenite::tungstenite::Error::Http(resp) = err else {
        panic!("expected an HTTP rejection, got {err:?}");
    };
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let (mut ws, _) = connect(gw, "graphql-transport-ws", Some("ws-key"))
        .await
        .expect("authed handshake succeeds");

    let denied = r#"{"id":"1","type":"subscribe","payload":{"query":"subscription { secret }"}}"#;
    ws.send(Message::text(denied)).await.expect("send denied");
    let reply = recv(&mut ws).await;
    let json: serde_json::Value =
        serde_json::from_str(reply.to_text().expect("text")).expect("json");
    assert_eq!(json["type"], "error");
    assert_eq!(json["id"], "1");
    assert_eq!(
        json["payload"][0]["message"],
        "field: secret is restricted on type: Subscription"
    );

    // The next allowed operation is the first thing the upstream sees.
    let allowed = r#"{"id":"2","type":"subscribe","payload":{"query":"subscription { ticks }"}}"#;
    ws.send(Message::text(allowed)).await.expect("send allowed");
    let next = recv(&mut ws).await;
    assert!(next.to_text().expect("text").contains("\"next\""));
    let seen = log.lock().expect("log").clone();
    assert_eq!(
        seen,
        vec![allowed.to_owned()],
        "denied subscribe never crossed"
    );
}

#[tokio::test]
async fn depth_violation_is_denied_at_the_gateway() {
    let (upstream, log) = spawn_graphql_ws_upstream(Some("graphql-transport-ws")).await;
    let def = subscriptions_api(&format!("http://{upstream}"), Some(1));
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let (gw, _stop) = spawn_gateway(vec![def], storage).await;

    let (mut ws, _) = connect(gw, "graphql-transport-ws", None)
        .await
        .expect("handshake succeeds");
    // Depth 2 > the API's limit of 1 (subscribe may carry any operation).
    let deep = r#"{"id":"1","type":"subscribe","payload":{"query":"query { nested { leaf } }"}}"#;
    ws.send(Message::text(deep)).await.expect("send deep");
    let reply = recv(&mut ws).await;
    assert!(
        reply
            .to_text()
            .expect("text")
            .contains("depth limit exceeded"),
        "got: {reply:?}"
    );
    assert!(log.lock().expect("log").is_empty(), "nothing crossed");
}

#[tokio::test]
async fn legacy_protocol_session_polices_start() {
    let (upstream, log) = spawn_graphql_ws_upstream(Some("graphql-ws")).await;
    let def = subscriptions_api(&format!("http://{upstream}"), Some(1));
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let (gw, _stop) = spawn_gateway(vec![def], storage).await;

    let (mut ws, resp) = connect(gw, "graphql-ws", None)
        .await
        .expect("handshake succeeds");
    assert_eq!(
        resp.headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("graphql-ws")
    );

    // Denied under the legacy vocabulary: error payload is an object.
    let deep = r#"{"id":"1","type":"start","payload":{"query":"query { nested { leaf } }"}}"#;
    ws.send(Message::text(deep)).await.expect("send deep");
    let reply = recv(&mut ws).await;
    let json: serde_json::Value =
        serde_json::from_str(reply.to_text().expect("text")).expect("json");
    assert_eq!(json["type"], "error");
    assert_eq!(json["payload"]["message"], "depth limit exceeded");

    // An allowed start crosses; a modern-only `subscribe` closes the
    // tunnel under the legacy vocabulary.
    let allowed = r#"{"id":"2","type":"start","payload":{"query":"subscription { ticks }"}}"#;
    ws.send(Message::text(allowed)).await.expect("send allowed");
    assert!(recv(&mut ws)
        .await
        .to_text()
        .expect("text")
        .contains("next"));
    assert_eq!(log.lock().expect("log").clone(), vec![allowed.to_owned()]);

    ws.send(Message::text(
        r#"{"id":"3","type":"subscribe","payload":{"query":"subscription { ticks }"}}"#,
    ))
    .await
    .expect("send modern message");
    // The legacy close is announced with a connection_error notice first.
    let notice = recv(&mut ws).await;
    assert!(
        notice.to_text().expect("text").contains("connection_error"),
        "got: {notice:?}"
    );
    assert!(matches!(recv(&mut ws).await, Message::Close(_)));
}

#[tokio::test]
async fn handshake_is_rejected_without_subscriptions_enabled() {
    let (upstream, _log) = spawn_graphql_ws_upstream(Some("graphql-transport-ws")).await;
    // A GraphQL API without a subscriptions block.
    let def: ApiDefinition = serde_json::from_value(serde_json::json!({
        "api_id": "subs",
        "name": "subs",
        "listen_path": "/gql/",
        "target_url": format!("http://{upstream}"),
        "auth": { "mode": "keyless" },
        "graphql": { "schema": SCHEMA },
    }))
    .expect("definition");
    def.validate().expect("valid definition");
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let (gw, _stop) = spawn_gateway(vec![def], storage).await;

    let err = connect(gw, "graphql-transport-ws", None)
        .await
        .expect_err("handshake is refused");
    let tokio_tungstenite::tungstenite::Error::Http(resp) = err else {
        panic!("expected an HTTP rejection, got {err:?}");
    };
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unpoliceable_upstream_subprotocol_is_a_502() {
    // The upstream negotiates a subprotocol the gateway cannot police.
    let (upstream, log) = spawn_graphql_ws_upstream(Some("soap-over-ws")).await;
    let def = subscriptions_api(&format!("http://{upstream}"), None);
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let (gw, _stop) = spawn_gateway(vec![def], storage).await;

    let err = connect(gw, "graphql-transport-ws", None)
        .await
        .expect_err("no tunnel over an unpoliceable subprotocol");
    let tokio_tungstenite::tungstenite::Error::Http(resp) = err else {
        panic!("expected an HTTP rejection, got {err:?}");
    };
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(log.lock().expect("log").is_empty());
}
