# gRPC passthrough

gRPC traffic passes through the gateway as opaque end-to-end HTTP/2:

- **All gRPC shapes work** — unary, server-streaming, client-streaming, and
  bidirectional — because the gateway never buffers proxied bodies: request
  and response messages stream through frame by frame, and response
  *trailers* (where gRPC carries `grpc-status`/`grpc-message`) are
  forwarded as trailer frames.
- **The client-facing side needs no configuration.** The plaintext listener
  detects HTTP/2 by its connection preface (h2c prior knowledge — what
  gRPC clients speak to a plaintext endpoint), and TLS listeners negotiate
  `h2` via ALPN.
- **The upstream side is a per-API opt-in** via `upstream_http2`, because
  the upstream leg is otherwise HTTP/1.1 — which silently breaks gRPC (no
  trailers, wrong protocol).

## Configuration

```json
{
  "api_id": "billing-grpc",
  "name": "Billing gRPC",
  "listen_path": "/billing.Billing/",
  "target_url": "http://billing.internal:50051",
  "strip_listen_path": false,
  "auth": {"mode": "keyless"},
  "upstream_http2": true
}
```

`upstream_http2` defaults to `false`: upstream requests stay HTTP/1.1 and
existing APIs are unchanged. The flag is per-version overridable
(`versions.<name>.upstream_http2`), and it applies to **all** of the API's
upstream traffic, gRPC or not — plain REST calls on the same API are also
sent over HTTP/2.

A gRPC service's fully-qualified name makes a natural `listen_path`
(`/billing.Billing/` above, matching paths like
`/billing.Billing/CreateInvoice`) — but gRPC request paths are always
`/package.Service/Method` and the upstream expects them whole, so a
service-name listen path needs `"strip_listen_path": false` (the default
strip would truncate the path to `/Method`).

### Semantics

- **`http://` targets speak h2c prior knowledge; `https://` targets offer
  only `h2` via ALPN.** There is no HTTP/1.1 fallback in either case: an
  upstream that cannot speak HTTP/2 fails the connection and the request
  maps to `502`.
- **`te: trailers` is preserved.** `te` is a hop-by-hop header and is
  normally stripped, but it is required by gRPC and is the one `te` value
  HTTP/2 permits (RFC 9113 §8.2.2); any other `te` value stays stripped.
- **The middleware chain runs against request headers as usual.** Auth,
  rate limits, IP filters, path lists, header transforms, and analytics
  all apply to a gRPC call like any POST; gRPC clients carry credentials
  in ordinary headers (`authorization`), so token/JWT/OIDC/mTLS modes work
  unchanged.
- **`upstream_timeout_ms` bounds response headers only.** Long-lived
  streaming RPCs survive it, exactly like SSE; gRPC deadlines belong to
  the client (`grpc-timeout` passes through untouched).
- **gRPC calls are never retried and never cached.** Retries only apply to
  idempotent empty-body requests, and the response cache only stores safe
  methods — gRPC is always POST, so neither engages.
- **The circuit breaker sees transport and HTTP-level failures only.** A
  gRPC error is an HTTP `200` with a non-zero `grpc-status` trailer and
  does not count as a breaker failure; connection failures and genuine
  `5xx` responses do.
- **Health-check probes use the HTTP/2 client too**, so a pure-HTTP/2
  upstream (a plain tonic server, say) is probed in a protocol it accepts.
  The probe is still `GET {path}` expecting `2xx` — point it at an
  HTTP-serving health path, or a grpc-web/health sidecar, not at a gRPC
  method.
- **Load balancing rotates per call** across `target_list` as usual; the
  HTTP/2 client multiplexes calls onto pooled connections per address.
- **Incompatible with `enable_upgrades`** (validation error): an HTTP/1.1
  `Connection: Upgrade` cannot cross an HTTP/2-only upstream connection.

## Verification

Covered by `crates/g2way/tests/grpc_e2e.rs`: a gRPC-shaped call (POST
`application/grpc`, `te: trailers`, length-prefixed message body) from an
HTTP/2 prior-knowledge client through a real gateway to an HTTP/2-only
upstream — asserting the upstream saw HTTP/2 with `te: trailers` intact and
the `grpc-status` trailer reached the client as a trailer — plus the
default-off HTTP/1.1 behavior and a versioned API mixing HTTP/1.1 and
HTTP/2 upstreams. The h2c, ALPN, and `te` details are unit-tested in
`crates/g2-proxy/src/forward.rs`.

## Limitations

- **Passthrough only.** No gRPC-Web translation, no gRPC↔REST
  transcoding, no message-level inspection, metrics, or transforms — the
  gateway sees frames, not protobuf.
- **Trailers to HTTP/1.1 clients follow chunked-trailer rules.** A plain
  HTTP/1.1 client calling an `upstream_http2` API gets the response
  translated to HTTP/1.1; real gRPC clients always speak HTTP/2, so this
  only affects hand-rolled callers.
- **Do not put gRPC traffic behind a `graphql` block**: the GraphQL layer
  buffers request bodies to parse them, which destroys request streaming.
- Analytics request/response sizes come from `Content-Length`, which gRPC
  messages usually omit — size fields on analytics records are empty for
  gRPC traffic.
