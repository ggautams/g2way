# WebSocket & SSE passthrough

Two kinds of long-lived streaming traffic pass through the gateway:

- **`Connection: Upgrade` tunneling** (WebSocket being the protocol that
  matters) is a per-API opt-in via `enable_upgrades`. The HTTP/1.1 upgrade
  *request* runs the full middleware chain; once the upstream answers
  `101 Switching Protocols`, the gateway splices the two connections
  together and shuttles raw bytes both ways until either side closes.
- **Server-sent events** (and any other long-poll/streamed response) need
  no configuration: response bodies always stream through the gateway
  frame by frame, and the per-API `upstream_timeout_ms` only bounds the
  wait for response *headers*, never an in-flight stream.

## WebSocket / upgrade configuration

```json
{
  "api_id": "chat",
  "name": "Chat",
  "listen_path": "/chat/",
  "target_url": "http://chat.internal:8000",
  "enable_upgrades": true
}
```

`enable_upgrades` defaults to `false`: without it, `Connection`/`Upgrade`
are stripped like every other hop-by-hop header (RFC 9110 §7.6.1) and the
request is proxied as plain HTTP — existing APIs are unchanged. The flag is
per-version overridable (`versions.<name>.enable_upgrades`).

### Semantics

- **The chain still applies to the handshake.** Auth, rate limits, quotas,
  IP filters, path lists, URL rewrites, and analytics all run against the
  upgrade request; a `401`/`403`/`429` simply means no tunnel. A WebSocket
  handshake is a `GET`, so token auth, JWT, and mTLS all work as usual —
  browser WebSocket clients cannot set an `Authorization` header, so those
  APIs typically use a query-param token carrier or `ignore_auth_paths`.
- **Established tunnels are opaque.** After the `101` the gateway copies
  bytes without interpreting them: no per-message metrics, no response
  transforms, no size limits inside the tunnel. Each tunnel occupies one
  gateway↔client and one gateway↔upstream connection for its lifetime.
- **Timeouts.** `upstream_timeout_ms` bounds the upgrade handshake (request
  out → `101` back). The tunnel itself has no idle or lifetime cap — the
  endpoints own keep-alive (WebSocket ping/pong).
- **Graceful shutdown does not drain tunnels.** A SIGTERM stops the accept
  loop and waits for in-flight *requests*; open tunnels live until the
  drain grace expires and the process exits. Clients should expect
  reconnects on deploys.
- **HTTP/1.1 only end to end.** An HTTP/2 client stream cannot carry an
  HTTP/1.1 upgrade, so requests arriving over h2 (possible on TLS
  listeners via ALPN) are proxied plain; WebSocket clients negotiate
  HTTP/1.1 themselves. RFC 8441 extended CONNECT is not supported.
- **Load balancing, health checks, retries, and the circuit breaker** apply
  to the handshake exactly as to any other request (a `101` counts as a
  breaker success; transport failures during the handshake are retried for
  the usual idempotent empty-body requests).
- An upstream that answers `101` when the gateway did not forward an
  upgrade request gets mapped to `502 unexpected upgrade response from
  upstream`.

## SSE notes

- Nothing to configure; keyless and authenticated APIs both stream.
- **Do not enable `cache` on an API serving SSE endpoints**: the cache
  layer tees safe-method `2xx` responses hoping to store them, and an
  endless stream is buffered up to the cache's `max_body_bytes` per request
  for nothing (it is never stored, since the body never completes). Put
  cacheable REST and SSE on different APIs or versions.
- Event delivery latency through the gateway is one body-frame copy; there
  is no gateway-side aggregation or flush delay.
- The number of concurrent SSE connections is bounded only by file
  descriptors and memory, like any proxy. Rate/quota limits count the
  initial request, not the stream's duration.

## Verification

Covered by `crates/g2way/tests/streaming_e2e.rs`: a WebSocket-style
echo upgrade through a real gateway (raw `101` handshake + bidirectional
bytes + teardown), the default-off downgrade to plain HTTP, and an SSE
stream that outlives `upstream_timeout_ms` while provably streaming (the
client receives event one while the upstream still withholds event two).

gRPC passthrough is a separate feature: it needs end-to-end HTTP/2 and
trailer forwarding rather than upgrade tunneling, and is enabled per API
with `upstream_http2` — see `docs/grpc.md`.
