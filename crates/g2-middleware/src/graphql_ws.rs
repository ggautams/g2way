//! GraphQL subscriptions over WebSocket (milestone M9, ADR-0009): the
//! policed relay behind [`GraphQlLayer`](crate::graphql::GraphQlLayer).
//!
//! The gateway **terminates** the graphql-over-WebSocket subprotocols
//! rather than tunneling opaque bytes (the M8+ `enable_upgrades` splice):
//! every client `subscribe` (graphql-transport-ws) / `start` (legacy
//! graphql-ws) payload is parsed with apollo-compiler against the API's
//! current schema and run through the same protection pipeline as an HTTP
//! query — introspection control, depth limits, per-key field permissions.
//! Violations are answered with protocol-level `error` messages carrying
//! the operation's `id` and never reach the upstream; permitted messages
//! are forwarded as their original text, and every upstream frame is
//! relayed verbatim (responses are the upstream's own data, exactly like
//! the HTTP path).
//!
//! The HTTP upgrade handshakes stay on hyper's passthrough on both legs —
//! the client's `Sec-WebSocket-Key`/`-Accept` pair crosses the gateway
//! end to end — so this module only speaks the *frame* layer, wrapping the
//! two already-upgraded streams with
//! [`WebSocketStream::from_raw_socket`].
//!
//! Fail-closed stance (ADR-0005 §4 precedent): anything the gateway cannot
//! police — an invalid JSON text frame, an unknown message type, a binary
//! frame, an upstream that negotiates a subprotocol outside the pair —
//! ends the connection instead of passing through unchecked.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use g2_core::session::ApiAccess;
use http::HeaderValue;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::graphql::{check_document, diagnostic_messages, GraphQlShared};

/// The modern graphql-over-WebSocket subprotocol name (the `graphql-ws`
/// npm library's `graphql-transport-ws` protocol).
pub(crate) const PROTO_GRAPHQL_TRANSPORT_WS: &str = "graphql-transport-ws";

/// The legacy subprotocol name (Apollo's `subscriptions-transport-ws`).
pub(crate) const PROTO_GRAPHQL_WS: &str = "graphql-ws";

/// The graphql-transport-ws close code for a protocol violation ("4400:
/// Bad Request" in the spec's registry).
const CLOSE_BAD_REQUEST: u16 = 4400;

/// Which message vocabulary the relay polices, derived from the
/// subprotocol the upstream's `101` named. An upstream that echoed no
/// `Sec-WebSocket-Protocol` gets [`Union`](Self::Union): both vocabularies
/// are understood, and gateway-emitted errors take the shape of the
/// protocol the offending message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vocab {
    /// graphql-transport-ws only.
    Modern,
    /// Legacy graphql-ws only.
    Legacy,
    /// Both (no subprotocol echoed by the upstream).
    Union,
}

/// The error-message dialect for one policed operation: `subscribe` gets
/// graphql-transport-ws shapes, `start` gets legacy shapes — regardless of
/// [`Vocab`], since the message itself names its protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorStyle {
    /// `{"id", "type": "error", "payload": [{"message"}…]}`.
    Modern,
    /// `{"type": "error", "id", "payload": {"message"}}`.
    Legacy,
}

/// What to do with one client text frame.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Relay the original text upstream. `operation` marks a policed
    /// subscribe/start that passed (for the tunnel's close-time counters).
    Forward {
        /// Whether this was a policed operation (vs. a control message).
        operation: bool,
    },
    /// Do not forward; send this protocol `error` message back to the
    /// client and keep the connection open.
    Reply(String),
    /// Protocol violation: close both sides. `notice` is a text message
    /// sent to the client first (the legacy protocol's `connection_error`).
    Close {
        /// Optional pre-close text message to the client.
        notice: Option<String>,
        /// WebSocket close code.
        code: u16,
        /// Close reason, also used for logging.
        reason: String,
    },
}

/// Request extension stamped by the GraphQL layer on a recognized
/// subscription WebSocket handshake.
///
/// The forwarder removes it alongside hyper's `OnUpgrade` handle; when the
/// upstream answers `101`, the tunnel task calls [`run`](Self::run) with
/// the two upgraded streams instead of splicing them opaquely (and answers
/// `502` without tunneling when [`accepts`](Self::accepts) rejects the
/// negotiated subprotocol).
#[derive(Debug, Clone)]
pub struct GraphQlWsTunnel {
    shared: Arc<GraphQlShared>,
    /// The key's per-API grants, snapshotted at handshake time (a key
    /// revoked mid-tunnel is not re-checked — same as M8 tunnels).
    grants: Option<ApiAccess>,
}

impl GraphQlWsTunnel {
    /// Builds the extension for one handshake.
    pub(crate) fn new(shared: Arc<GraphQlShared>, grants: Option<ApiAccess>) -> Self {
        Self { shared, grants }
    }

    /// Whether the gateway can police the subprotocol the upstream's `101`
    /// named in `Sec-WebSocket-Protocol`. `None` (nothing echoed) is
    /// acceptable — the relay then polices the union of both vocabularies.
    #[must_use]
    pub fn accepts(&self, negotiated: Option<&HeaderValue>) -> bool {
        match negotiated {
            None => true,
            Some(value) => value.to_str().is_ok_and(|name| {
                matches!(name.trim(), PROTO_GRAPHQL_TRANSPORT_WS | PROTO_GRAPHQL_WS)
            }),
        }
    }

    /// Runs the policed relay over the two upgraded streams until either
    /// side closes (or a protocol violation closes both). `negotiated` is
    /// the upstream `101`'s `Sec-WebSocket-Protocol` value, already vetted
    /// by [`accepts`](Self::accepts).
    ///
    /// Called from the forwarder's detached tunnel task; logs a summary
    /// (operations allowed/denied) at close.
    pub async fn run<C, U>(self, client: C, upstream: U, negotiated: Option<HeaderValue>)
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let vocab = match negotiated
            .as_ref()
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
        {
            Some(PROTO_GRAPHQL_TRANSPORT_WS) => Vocab::Modern,
            Some(PROTO_GRAPHQL_WS) => Vocab::Legacy,
            // `accepts` gates unknown names; nothing echoed = union.
            _ => Vocab::Union,
        };
        // The client leg carries the configured message cap; the upstream
        // leg keeps tungstenite's defaults as a sanity bound only.
        let client_config =
            WebSocketConfig::default().max_message_size(Some(self.shared.ws_max_message_bytes));
        let client_ws =
            WebSocketStream::from_raw_socket(client, Role::Server, Some(client_config)).await;
        let upstream_ws = WebSocketStream::from_raw_socket(upstream, Role::Client, None).await;
        let (mut client_tx, mut client_rx) = client_ws.split();
        let (mut upstream_tx, mut upstream_rx) = upstream_ws.split();

        let api_id = self.shared.api_id.clone();
        let started = std::time::Instant::now();
        let (mut allowed, mut denied) = (0u64, 0u64);
        loop {
            tokio::select! {
                msg = client_rx.next() => match msg {
                    // Text frames are policed; a binary frame cannot be —
                    // it would cross unchecked, so it closes the tunnel.
                    Some(Ok(message @ (Message::Text(_) | Message::Binary(_)))) => {
                        let action = match &message {
                            Message::Text(text) => police_client_text(
                                &self.shared,
                                self.grants.as_ref(),
                                vocab,
                                text.as_str(),
                            ),
                            _ => violation_close(vocab, "binary frames are not supported"),
                        };
                        match action {
                            Action::Forward { operation } => {
                                if operation {
                                    allowed += 1;
                                }
                                if upstream_tx.send(message).await.is_err() {
                                    break;
                                }
                            }
                            Action::Reply(reply) => {
                                denied += 1;
                                if client_tx.send(Message::text(reply)).await.is_err() {
                                    break;
                                }
                            }
                            Action::Close { notice, code, reason } => {
                                tracing::debug!(
                                    %api_id, %reason,
                                    "closing graphql subscription tunnel on protocol violation"
                                );
                                if let Some(notice) = notice {
                                    let _ = client_tx.send(Message::text(notice)).await;
                                }
                                let frame = CloseFrame {
                                    code: CloseCode::from(code),
                                    reason: reason.into(),
                                };
                                let _ = client_tx.send(Message::Close(Some(frame.clone()))).await;
                                let _ = upstream_tx.send(Message::Close(Some(frame))).await;
                                break;
                            }
                        }
                    }
                    // WebSocket-level pings are leg-local (RFC 6455 — the
                    // nearest endpoint answers): tungstenite queues the
                    // pong on read, the flush pushes it out. GraphQL-level
                    // `ping`/`pong` JSON messages are relayed above.
                    Some(Ok(Message::Ping(_))) => {
                        let _ = client_tx.flush().await;
                    }
                    Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        let _ = upstream_tx.send(Message::Close(frame)).await;
                        break;
                    }
                    Some(Err(err)) => {
                        tracing::debug!(%api_id, error = %err, "client leg failed");
                        let _ = upstream_tx.send(Message::Close(None)).await;
                        break;
                    }
                    None => {
                        let _ = upstream_tx.send(Message::Close(None)).await;
                        break;
                    }
                },
                msg = upstream_rx.next() => match msg {
                    Some(Ok(Message::Ping(_))) => {
                        let _ = upstream_tx.flush().await;
                    }
                    Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        let _ = client_tx.send(Message::Close(frame)).await;
                        break;
                    }
                    // Everything else — `next`/`data`, `error`, `complete`,
                    // `ka`, `connection_ack` — is the upstream's own data:
                    // relayed verbatim, never parsed (like HTTP responses).
                    Some(Ok(message)) => {
                        if client_tx.send(message).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(err)) => {
                        tracing::debug!(%api_id, error = %err, "upstream leg failed");
                        let _ = client_tx.send(Message::Close(None)).await;
                        break;
                    }
                    None => {
                        let _ = client_tx.send(Message::Close(None)).await;
                        break;
                    }
                },
            }
        }
        // Best-effort close handshakes for whichever side is still up.
        let _ = client_tx.close().await;
        let _ = upstream_tx.close().await;
        tracing::debug!(
            %api_id,
            ops_allowed = allowed,
            ops_denied = denied,
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "graphql subscription tunnel closed"
        );
    }
}

/// The parts of a client message the gateway reads. `payload` stays raw
/// JSON: only `subscribe`/`start` payloads are inspected further —
/// `connection_init` carries an arbitrary (often auth) payload that is
/// none of the gateway's business.
#[derive(serde::Deserialize)]
struct Inbound {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
}

/// Decides what to do with one client text frame: police
/// `subscribe`/`start` payloads, relay other known message types, and
/// fail closed on anything outside `vocab`.
fn police_client_text(
    shared: &GraphQlShared,
    grants: Option<&ApiAccess>,
    vocab: Vocab,
    text: &str,
) -> Action {
    let Ok(message) = serde_json::from_str::<Inbound>(text) else {
        return violation_close(vocab, "invalid message: not a graphql-ws JSON object");
    };
    let modern_kind = matches!(
        message.kind.as_str(),
        "connection_init" | "ping" | "pong" | "subscribe" | "complete"
    );
    let legacy_kind = matches!(
        message.kind.as_str(),
        "connection_init" | "start" | "stop" | "connection_terminate"
    );
    let known = match vocab {
        Vocab::Modern => modern_kind,
        Vocab::Legacy => legacy_kind,
        Vocab::Union => modern_kind || legacy_kind,
    };
    if !known {
        return violation_close(vocab, &format!("unknown message type: {}", message.kind));
    }
    let style = match message.kind.as_str() {
        "subscribe" => ErrorStyle::Modern,
        "start" => ErrorStyle::Legacy,
        // Control messages pass through untouched.
        _ => return Action::Forward { operation: false },
    };
    // Both protocols require an id on an operation; without one there is
    // nothing to address an `error` message to, so the violation closes.
    if message.id.is_none() {
        return violation_close(vocab, &format!("{} message without an id", message.kind));
    }
    police_operation(shared, grants, style, message.id, message.payload.as_ref())
}

/// Polices one `subscribe`/`start` payload: parse and validate the query
/// against the current schema state, then run the shared protection
/// pipeline. The payload may carry any operation type (the protocols
/// allow queries and mutations too) — all are policed alike.
fn police_operation(
    shared: &GraphQlShared,
    grants: Option<&ApiAccess>,
    style: ErrorStyle,
    id: Option<serde_json::Value>,
    payload: Option<&serde_json::Value>,
) -> Action {
    let query = payload
        .and_then(|p| p.get("query"))
        .and_then(serde_json::Value::as_str)
        .filter(|q| !q.trim().is_empty());
    let Some(query) = query else {
        return Action::Reply(error_message(
            style,
            id,
            vec!["the request is missing a GraphQL query".to_owned()],
        ));
    };
    // One wait-free load per operation (ADR-0006/0008 rule): a schema sync
    // mid-tunnel applies to every later subscribe.
    let state = shared.state.load_full();
    let doc = match apollo_compiler::ExecutableDocument::parse_and_validate(
        &state.schema,
        query,
        "subscription.graphql",
    ) {
        Ok(doc) => doc,
        Err(e) => return Action::Reply(error_message(style, id, diagnostic_messages(&e.errors))),
    };
    match check_document(shared, grants, &doc) {
        Ok(()) => Action::Forward { operation: true },
        Err(violation) => Action::Reply(error_message(style, id, vec![violation.message()])),
    }
}

/// Renders a protocol `error` message for a denied operation.
fn error_message(
    style: ErrorStyle,
    id: Option<serde_json::Value>,
    messages: Vec<String>,
) -> String {
    match style {
        ErrorStyle::Modern => {
            let errors: Vec<serde_json::Value> = messages
                .into_iter()
                .map(|m| serde_json::json!({ "message": m }))
                .collect();
            serde_json::json!({ "id": id, "type": "error", "payload": errors }).to_string()
        }
        ErrorStyle::Legacy => serde_json::json!({
            "type": "error",
            "id": id,
            "payload": { "message": messages.join("; ") },
        })
        .to_string(),
    }
}

/// A fail-closed protocol violation: graphql-transport-ws closes with the
/// spec's `4400` code; the legacy protocol sends a `connection_error`
/// message first and closes `1002` (protocol error). [`Vocab::Union`] uses
/// the modern shape.
fn violation_close(vocab: Vocab, reason: &str) -> Action {
    match vocab {
        Vocab::Legacy => Action::Close {
            notice: Some(
                serde_json::json!({
                    "type": "connection_error",
                    "payload": { "message": reason },
                })
                .to_string(),
            ),
            code: 1002,
            reason: reason.to_owned(),
        },
        Vocab::Modern | Vocab::Union => Action::Close {
            notice: None,
            code: CLOSE_BAD_REQUEST,
            reason: reason.to_owned(),
        },
    }
}

/// Whether a request is a WebSocket upgrade handshake: `GET` with a
/// `Connection` header carrying the `upgrade` token and an `Upgrade:
/// websocket` header (both token lists, case-insensitive — mirroring the
/// forwarder's upgrade detection).
pub(crate) fn is_websocket_handshake<B>(req: &http::Request<B>) -> bool {
    fn has_token(value: Option<&HeaderValue>, token: &str) -> bool {
        value
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }
    req.method() == http::Method::GET
        && has_token(req.headers().get(http::header::CONNECTION), "upgrade")
        && has_token(req.headers().get(http::header::UPGRADE), "websocket")
}

/// Whether the client's `Sec-WebSocket-Protocol` offer (possibly several
/// headers, each a comma-separated list) names at least one subprotocol
/// the gateway polices.
pub(crate) fn offers_known_protocol(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|name| matches!(name.trim(), PROTO_GRAPHQL_TRANSPORT_WS | PROTO_GRAPHQL_WS))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::graphql::GraphQlLayer;
    use g2_core::session::TypeFields;
    use g2_core::ApiDefinition;

    const SCHEMA: &str = "type Query { hello: String nested: Nested } \
                          type Nested { deep: Nested leaf: String } \
                          type Subscription { ticks: Int secret: String }";

    /// A subscriptions-enabled shared state, optionally with a tiny
    /// message cap.
    fn shared(max_message_bytes: Option<u64>) -> Arc<GraphQlShared> {
        let def: ApiDefinition = serde_json::from_value(serde_json::json!({
            "api_id": "gql",
            "name": "gql",
            "listen_path": "/gql/",
            "target_url": "http://u.internal",
            "auth": { "mode": "keyless" },
            "graphql": {
                "schema": SCHEMA,
                "max_query_depth": 3,
                "subscriptions": { "max_message_bytes": max_message_bytes },
            },
        }))
        .expect("definition");
        def.validate().expect("valid definition");
        let config = def.graphql.clone().expect("graphql block");
        GraphQlLayer::from_config(&config, &def, None, None)
            .expect("layer builds")
            .expect("enabled")
            .shared
    }

    fn police(vocab: Vocab, text: &str) -> Action {
        police_client_text(&shared(None), None, vocab, text)
    }

    fn restrictive_grants() -> ApiAccess {
        ApiAccess {
            restricted_types: vec![TypeFields {
                name: "Subscription".into(),
                fields: vec!["secret".into()],
            }],
            ..ApiAccess::default()
        }
    }

    #[test]
    fn valid_subscribe_forwards_as_an_operation() {
        let msg = r#"{"id":"1","type":"subscribe","payload":{"query":"subscription { ticks }"}}"#;
        assert_eq!(
            police(Vocab::Modern, msg),
            Action::Forward { operation: true }
        );
        // The same operation as a legacy `start`.
        let legacy = r#"{"id":"1","type":"start","payload":{"query":"subscription { ticks }"}}"#;
        assert_eq!(
            police(Vocab::Legacy, legacy),
            Action::Forward { operation: true }
        );
        // Union accepts both.
        assert_eq!(
            police(Vocab::Union, msg),
            Action::Forward { operation: true }
        );
        assert_eq!(
            police(Vocab::Union, legacy),
            Action::Forward { operation: true }
        );
    }

    #[test]
    fn control_messages_are_relayed_unpoliced() {
        for msg in [
            r#"{"type":"connection_init","payload":{"Authorization":"Bearer t"}}"#,
            r#"{"type":"ping"}"#,
            r#"{"type":"pong"}"#,
            r#"{"id":"1","type":"complete"}"#,
        ] {
            assert_eq!(
                police(Vocab::Modern, msg),
                Action::Forward { operation: false },
                "modern: {msg}"
            );
        }
        for msg in [
            r#"{"type":"connection_init"}"#,
            r#"{"id":"1","type":"stop"}"#,
            r#"{"type":"connection_terminate"}"#,
        ] {
            assert_eq!(
                police(Vocab::Legacy, msg),
                Action::Forward { operation: false },
                "legacy: {msg}"
            );
        }
    }

    #[test]
    fn forbidden_field_is_denied_with_the_field_message_and_the_id() {
        let msg = r#"{"id":"7","type":"subscribe","payload":{"query":"subscription { secret }"}}"#;
        let action = police_client_text(
            &shared(None),
            Some(&restrictive_grants()),
            Vocab::Modern,
            msg,
        );
        let Action::Reply(reply) = action else {
            panic!("expected a reply, got {action:?}");
        };
        let json: serde_json::Value = serde_json::from_str(&reply).expect("reply is JSON");
        assert_eq!(json["type"], "error");
        assert_eq!(json["id"], "7");
        assert_eq!(
            json["payload"][0]["message"],
            "field: secret is restricted on type: Subscription"
        );
    }

    #[test]
    fn legacy_error_shape_is_an_object_payload() {
        let msg = r#"{"id":"9","type":"start","payload":{"query":"subscription { secret }"}}"#;
        let action = police_client_text(
            &shared(None),
            Some(&restrictive_grants()),
            Vocab::Legacy,
            msg,
        );
        let Action::Reply(reply) = action else {
            panic!("expected a reply, got {action:?}");
        };
        let json: serde_json::Value = serde_json::from_str(&reply).expect("reply is JSON");
        assert_eq!(json["type"], "error");
        assert_eq!(json["id"], "9");
        assert_eq!(
            json["payload"]["message"],
            "field: secret is restricted on type: Subscription"
        );
    }

    #[test]
    fn depth_and_validation_violations_are_denied() {
        // Depth 4 > the API's limit of 3.
        let deep = r#"{"id":"1","type":"subscribe","payload":{"query":"query { nested { deep { deep { leaf } } } }"}}"#;
        let Action::Reply(reply) = police(Vocab::Modern, deep) else {
            panic!("expected a reply");
        };
        assert!(reply.contains("depth limit exceeded"), "got: {reply}");

        // A field the schema does not define.
        let invalid =
            r#"{"id":"1","type":"subscribe","payload":{"query":"subscription { nope }"}}"#;
        let Action::Reply(reply) = police(Vocab::Modern, invalid) else {
            panic!("expected a reply");
        };
        assert!(reply.contains("nope"), "got: {reply}");
    }

    #[test]
    fn missing_query_and_missing_id_are_rejected() {
        let no_query = r#"{"id":"1","type":"subscribe","payload":{}}"#;
        let Action::Reply(reply) = police(Vocab::Modern, no_query) else {
            panic!("expected a reply");
        };
        assert!(reply.contains("missing a GraphQL query"), "got: {reply}");

        let no_id = r#"{"type":"subscribe","payload":{"query":"subscription { ticks }"}}"#;
        assert!(
            matches!(
                police(Vocab::Modern, no_id),
                Action::Close { code: 4400, .. }
            ),
            "an id-less operation cannot be addressed by an error message"
        );
    }

    #[test]
    fn unknown_and_invalid_messages_fail_closed_per_protocol() {
        // Invalid JSON.
        assert!(matches!(
            police(Vocab::Modern, "not json"),
            Action::Close {
                code: 4400,
                notice: None,
                ..
            }
        ));
        // A legacy-only kind under the modern vocabulary.
        assert!(matches!(
            police(Vocab::Modern, r#"{"id":"1","type":"start"}"#),
            Action::Close { code: 4400, .. }
        ));
        // A modern-only kind under the legacy vocabulary, with the legacy
        // connection_error notice and 1002.
        let action = police(Vocab::Legacy, r#"{"id":"1","type":"subscribe"}"#);
        let Action::Close {
            notice: Some(notice),
            code: 1002,
            ..
        } = action
        else {
            panic!("expected a legacy close, got {action:?}");
        };
        assert!(notice.contains("connection_error"), "got: {notice}");
    }

    // ---- relay tests over in-memory duplex streams ----

    type TestWs = WebSocketStream<tokio::io::DuplexStream>;

    /// Spawns a relay for `shared`/`grants` and returns the test-side
    /// client (Role::Client, like a browser) and upstream (Role::Server,
    /// like a graphql-ws server) sockets.
    async fn spawn_relay(
        shared: Arc<GraphQlShared>,
        grants: Option<ApiAccess>,
        negotiated: Option<&str>,
    ) -> (TestWs, TestWs) {
        let (client_gw, client_test) = tokio::io::duplex(64 * 1024);
        let (upstream_gw, upstream_test) = tokio::io::duplex(64 * 1024);
        let tunnel = GraphQlWsTunnel::new(shared, grants);
        let negotiated = negotiated.map(|n| HeaderValue::from_str(n).expect("header value"));
        tokio::spawn(tunnel.run(client_gw, upstream_gw, negotiated));
        let client = WebSocketStream::from_raw_socket(client_test, Role::Client, None).await;
        let upstream = WebSocketStream::from_raw_socket(upstream_test, Role::Server, None).await;
        (client, upstream)
    }

    /// The next message on `ws`, with a test timeout.
    async fn recv(ws: &mut TestWs) -> Message {
        tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for a message")
            .expect("stream ended")
            .expect("frame ok")
    }

    #[tokio::test]
    async fn modern_session_relays_end_to_end() {
        let (mut client, mut upstream) =
            spawn_relay(shared(None), None, Some(PROTO_GRAPHQL_TRANSPORT_WS)).await;

        client
            .send(Message::text(r#"{"type":"connection_init"}"#))
            .await
            .expect("send init");
        assert_eq!(
            recv(&mut upstream).await,
            Message::text(r#"{"type":"connection_init"}"#)
        );
        upstream
            .send(Message::text(r#"{"type":"connection_ack"}"#))
            .await
            .expect("send ack");
        assert_eq!(
            recv(&mut client).await,
            Message::text(r#"{"type":"connection_ack"}"#)
        );

        let subscribe =
            r#"{"id":"1","type":"subscribe","payload":{"query":"subscription { ticks }"}}"#;
        client
            .send(Message::text(subscribe))
            .await
            .expect("send subscribe");
        assert_eq!(recv(&mut upstream).await, Message::text(subscribe));

        let next = r#"{"id":"1","type":"next","payload":{"data":{"ticks":1}}}"#;
        upstream.send(Message::text(next)).await.expect("send next");
        assert_eq!(recv(&mut client).await, Message::text(next));

        let complete = r#"{"id":"1","type":"complete"}"#;
        upstream
            .send(Message::text(complete))
            .await
            .expect("send complete");
        assert_eq!(recv(&mut client).await, Message::text(complete));

        // Client close propagates to the upstream.
        client.close(None).await.expect("close");
        assert!(matches!(recv(&mut upstream).await, Message::Close(_)));
    }

    #[tokio::test]
    async fn denied_subscribe_never_reaches_the_upstream() {
        let (mut client, mut upstream) = spawn_relay(
            shared(None),
            Some(restrictive_grants()),
            Some(PROTO_GRAPHQL_TRANSPORT_WS),
        )
        .await;

        let denied =
            r#"{"id":"1","type":"subscribe","payload":{"query":"subscription { secret }"}}"#;
        client
            .send(Message::text(denied))
            .await
            .expect("send denied");
        let reply = recv(&mut client).await;
        let text = reply.to_text().expect("text frame");
        assert!(
            text.contains("restricted on type: Subscription"),
            "got: {text}"
        );

        // The next *allowed* operation is the first thing the upstream
        // sees — proving the denied one was never forwarded.
        let allowed =
            r#"{"id":"2","type":"subscribe","payload":{"query":"subscription { ticks }"}}"#;
        client
            .send(Message::text(allowed))
            .await
            .expect("send allowed");
        assert_eq!(recv(&mut upstream).await, Message::text(allowed));
    }

    #[tokio::test]
    async fn legacy_session_polices_start_and_relays_ka() {
        let (mut client, mut upstream) = spawn_relay(
            shared(None),
            Some(restrictive_grants()),
            Some(PROTO_GRAPHQL_WS),
        )
        .await;

        upstream
            .send(Message::text(r#"{"type":"ka"}"#))
            .await
            .expect("send ka");
        assert_eq!(recv(&mut client).await, Message::text(r#"{"type":"ka"}"#));

        let denied = r#"{"id":"1","type":"start","payload":{"query":"subscription { secret }"}}"#;
        client
            .send(Message::text(denied))
            .await
            .expect("send start");
        let reply = recv(&mut client).await;
        let json: serde_json::Value =
            serde_json::from_str(reply.to_text().expect("text")).expect("json");
        assert_eq!(json["type"], "error");
        assert_eq!(
            json["payload"]["message"],
            "field: secret is restricted on type: Subscription"
        );

        let allowed = r#"{"id":"2","type":"start","payload":{"query":"subscription { ticks }"}}"#;
        client
            .send(Message::text(allowed))
            .await
            .expect("send allowed");
        assert_eq!(recv(&mut upstream).await, Message::text(allowed));
    }

    #[tokio::test]
    async fn binary_frame_closes_both_sides() {
        let (mut client, mut upstream) =
            spawn_relay(shared(None), None, Some(PROTO_GRAPHQL_TRANSPORT_WS)).await;
        client
            .send(Message::binary(vec![1u8, 2, 3]))
            .await
            .expect("send binary");
        assert!(matches!(recv(&mut client).await, Message::Close(_)));
        assert!(matches!(recv(&mut upstream).await, Message::Close(_)));
    }

    #[tokio::test]
    async fn oversized_message_ends_the_tunnel() {
        // A 64-byte cap on the client leg.
        let (mut client, mut upstream) =
            spawn_relay(shared(Some(64)), None, Some(PROTO_GRAPHQL_TRANSPORT_WS)).await;
        let huge = format!(
            r#"{{"id":"1","type":"subscribe","payload":{{"query":"subscription {{ ticks }} # {}"}}}}"#,
            "x".repeat(256)
        );
        client
            .send(Message::text(huge))
            .await
            .expect("send oversized");
        // The relay's client read errors on the cap and the upstream leg
        // is closed; nothing was forwarded.
        assert!(matches!(recv(&mut upstream).await, Message::Close(_)));
    }

    #[tokio::test]
    async fn upstream_close_propagates_to_the_client() {
        let (mut client, mut upstream) =
            spawn_relay(shared(None), None, Some(PROTO_GRAPHQL_TRANSPORT_WS)).await;
        upstream.close(None).await.expect("close upstream");
        assert!(matches!(recv(&mut client).await, Message::Close(_)));
    }

    #[tokio::test]
    async fn union_mode_polices_both_vocabularies() {
        // No subprotocol echoed by the upstream.
        let (mut client, mut upstream) =
            spawn_relay(shared(None), Some(restrictive_grants()), None).await;
        let modern_denied =
            r#"{"id":"1","type":"subscribe","payload":{"query":"subscription { secret }"}}"#;
        client
            .send(Message::text(modern_denied))
            .await
            .expect("send");
        assert!(recv(&mut client)
            .await
            .to_text()
            .expect("text")
            .contains("restricted"));

        let legacy_allowed =
            r#"{"id":"2","type":"start","payload":{"query":"subscription { ticks }"}}"#;
        client
            .send(Message::text(legacy_allowed))
            .await
            .expect("send");
        assert_eq!(recv(&mut upstream).await, Message::text(legacy_allowed));
    }

    // ---- handshake helper tests ----

    fn handshake_request(headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder()
            .method(http::Method::GET)
            .uri("/gql");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).expect("request")
    }

    #[test]
    fn websocket_handshakes_are_detected() {
        assert!(is_websocket_handshake(&handshake_request(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
        ])));
        // Token lists and case-insensitivity.
        assert!(is_websocket_handshake(&handshake_request(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "WebSocket"),
        ])));
        // A plain GET is not a handshake.
        assert!(!is_websocket_handshake(&handshake_request(&[])));
        // Upgrade to something else is not a WebSocket handshake.
        assert!(!is_websocket_handshake(&handshake_request(&[
            ("connection", "upgrade"),
            ("upgrade", "h2c"),
        ])));
        // POST cannot upgrade.
        let mut req = handshake_request(&[("connection", "upgrade"), ("upgrade", "websocket")]);
        *req.method_mut() = http::Method::POST;
        assert!(!is_websocket_handshake(&req));
    }

    #[test]
    fn protocol_offers_are_parsed_from_token_lists() {
        let known = handshake_request(&[(
            "sec-websocket-protocol",
            "something-else, graphql-transport-ws",
        )]);
        assert!(offers_known_protocol(known.headers()));

        let legacy = handshake_request(&[("sec-websocket-protocol", "graphql-ws")]);
        assert!(offers_known_protocol(legacy.headers()));

        let unknown = handshake_request(&[("sec-websocket-protocol", "soap-over-ws")]);
        assert!(!offers_known_protocol(unknown.headers()));

        let none = handshake_request(&[]);
        assert!(!offers_known_protocol(none.headers()));
    }

    #[test]
    fn accepts_vets_the_upstream_choice() {
        let tunnel = GraphQlWsTunnel::new(shared(None), None);
        assert!(tunnel.accepts(None));
        for ok in [PROTO_GRAPHQL_TRANSPORT_WS, PROTO_GRAPHQL_WS] {
            assert!(tunnel.accepts(Some(&HeaderValue::from_static(ok))), "{ok}");
        }
        assert!(!tunnel.accepts(Some(&HeaderValue::from_static("soap-over-ws"))));
    }
}
