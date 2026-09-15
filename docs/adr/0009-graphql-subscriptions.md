# ADR-0009: GraphQL subscriptions over WebSocket — terminate and police

Date: 2026-09-02 · Status: accepted

## Context

M9's subscriptions box was blocked on the M8+ upgrade passthrough, which
now exists — but that passthrough is deliberately opaque: after the `101`
the gateway splices raw bytes (`copy_bidirectional`) and interprets
nothing. GraphQL protections, by contrast, are the point of the GraphQL
feature (ADR-0004): schema validation, depth limits, introspection
control, and per-key field permissions all act on the *operation*, and for
subscriptions the operation travels inside WebSocket frames as
graphql-over-WebSocket protocol messages. An opaque tunnel would make
subscriptions "work" while silently exempting them from every protection a
query is subject to. ADR-0004 decision 7 left the how open.

## Decisions

1. **Terminate and police.** The gateway speaks the graphql-over-WebSocket
   subprotocols on both legs. Every client `subscribe`
   (graphql-transport-ws) / `start` (legacy graphql-ws) payload is parsed
   with apollo-compiler against the API's current schema and run through
   the same check pipeline as an HTTP query (`check_document` — shared
   code, not a copy); a violation is answered with a protocol-level
   `error` message carrying the operation's `id` and is never forwarded.
   Permitted client messages are forwarded as their original text;
   **upstream→client frames are relayed verbatim, never parsed** —
   responses are the upstream's own data, exactly as on the HTTP path.
   The alternative — handshake-time auth only, bytes opaque — is what
   `enable_upgrades` already provides and polices nothing.

2. **The HTTP handshakes stay on hyper's passthrough; only frames are
   terminated.** The client's `Sec-WebSocket-Key` crosses the gateway to
   the upstream, whose `Sec-WebSocket-Accept` crosses back — the gateway
   computes no accept key and needs no sha1. Once both `101`s complete,
   the two upgraded streams are wrapped with tungstenite's
   `WebSocketStream::from_raw_socket` (`Role::Server` toward the client,
   `Role::Client` toward the upstream — masking is re-applied correctly on
   each leg). This reuses the entire M8 handshake path: auth chain on the
   handshake, load balancing, service discovery, health eviction, circuit
   breaker, upstream timeout.

3. **Both subprotocols; the upstream's `101` is authoritative.** Clients
   offer `Sec-WebSocket-Protocol` and the upstream picks. The gateway
   polices whichever the upstream named — `graphql-transport-ws` or
   `graphql-ws` — and when a (lax, usually legacy) upstream echoes no
   subprotocol at all, it polices the **union** of both vocabularies,
   shaping each error by the protocol the offending message belongs to.
   Fail closed at both edges: a client offering neither known subprotocol
   is refused at the handshake (`400` — an unknown protocol inside the
   socket would bypass every protection), and an upstream negotiating an
   unknown subprotocol gets no tunnel (`502`, both pending protocol
   switches dropped).

4. **Codec dependency: tokio-tungstenite 0.30, `default-features =
   false`.** Frame codec only — no TLS, no handshake machinery in the
   shipped binary (the `handshake` feature is a test-only dev-dependency
   for driving real sessions). Pure Rust, MSRV 1.85 = ours. Hand-rolling
   RFC 6455 framing (masking, fragmentation, control-frame interleaving,
   close semantics) was rejected as a large, subtle surface for zero
   dependency savings.

5. **Policing semantics.**
   - `subscribe`/`start` payloads may carry any operation type (the
     protocols allow queries and mutations); all are policed alike. An
     operation without an `id` closes the connection — there is nothing to
     address the `error` message to.
   - `connection_init` (including its auth payload — the gateway does not
     interpret it), `ping`/`pong`, `complete`, `stop`,
     `connection_terminate` are relayed verbatim.
   - Invalid JSON, unknown message types, and binary frames close both
     sides (graphql-transport-ws: close `4400`; legacy: a
     `connection_error` message then close `1002`) — fail closed, the
     ADR-0005 §4 stance.
   - The client-leg message cap is `subscriptions.max_message_bytes`, else
     the API's `max_request_body_bytes`, else 1 MiB — the HTTP-side buffer
     bound.
   - WebSocket-level ping/pong control frames are **leg-local** (RFC 6455:
     the nearest endpoint answers); GraphQL-level `ping`/`pong` JSON
     messages are relayed.
   - Each policed operation loads the schema state once from the
     `ArcSwap` (ADR-0008): a schema sync mid-tunnel applies to every later
     subscribe.
6. **Configuration: `graphql.subscriptions {}`; upgrades implied.**
   Presence-as-enablement like `playground`. The block does **not**
   require `enable_upgrades: true`: on a GraphQL API every WebSocket
   handshake is either policed or rejected by the GraphQL layer, so the
   implied forwarder opt-in can never open an unpoliced tunnel. Validation
   requires a `Subscription` root in the schema and rejects
   `upstream_http2` (no HTTP/1.1 upgrade over an h2-only upstream — the
   `enable_upgrades` rule's mirror). Per-key grants gain nothing: the
   existing depth/field/introspection grants apply to subscribe payloads
   through the shared checks.

7. **Subscriptions over plain HTTP are now rejected** (`400`, "GraphQL
   subscriptions require a WebSocket connection") instead of
   blind-forwarded — a behavior change. Only the *executed* operation
   (resolved via `operationName`) is judged; a multi-operation document
   whose selected operation is a query still passes.

## Consequences

- The gateway↔middleware seam is a request extension (`GraphQlWsTunnel`)
  stamped by the GraphQL layer and consumed by the forwarder's upgrade
  path — g2-proxy already depends on g2-middleware, so no `JwksFetch`-
  style trait inversion is needed; tokio-tungstenite is a g2-middleware
  dependency only.
- Grants are snapshotted at handshake time: a key revoked mid-tunnel is
  not re-checked (same as M8 tunnels; reconnects re-authenticate).
- Subscription tunnels are excluded from graceful drain, like every
  upgrade tunnel — clients should expect reconnects on deploys.
- No per-message analytics/metrics inside the tunnel; the handshake is
  counted like any request. Message-level observability is future work.
- On GraphQL-subscription tunnels, WebSocket pings no longer cross the
  gateway end to end (they are answered leg-locally) — a behavioral
  difference from opaque `enable_upgrades` tunnels. Endpoint liveness
  keep-alive still works on each leg; GraphQL-level `ping`/`pong` crosses.
- `docs/websockets.md`'s "established tunnels are opaque" now carries a
  GraphQL-subscriptions exception.
