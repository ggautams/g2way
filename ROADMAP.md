# g2way roadmap

The feature set is delivered in milestones. Worked through
top to bottom; the first unchecked box is the next task. Architecture
decisions: `docs/adr/`.

## M0 — Scaffolding & workflow

- [x] Cargo workspace (7 crates), `rustfmt.toml`, workspace lints
- [x] `Makefile` with `check` gate (fmt + clippy -D warnings + tests + doc -D warnings)
- [x] `ROADMAP.md` (this file) seeded with all milestones
- [x] ADR-0001: stack choices (hyper/tower, Redis, OpenTelemetry)
- [x] git repo with initial commits

## M1 — Core reverse proxy

- [x] `ApiDefinition` v1 (listen_path, target_url, strip_listen_path, preserve_host_header, upstream_timeout_ms, active, org_id) with validation
- [x] File-based definition loading (`--apps-dir`, JSON/YAML, conflict detection)
- [x] Router: longest-prefix listen-path matching over an `ArcSwap` route table
- [x] Proxy engine: path strip/join, query passthrough, hop-by-hop header removal, `X-Forwarded-For/Host/Proto`, host rewrite vs preserve
- [x] Per-API upstream timeout → 504; unreachable upstream → 502; no route → 404 (JSON errors)
- [x] `/hello` + `/ready` health endpoints (served before routing)
- [x] Graceful shutdown on SIGTERM/SIGINT with drain grace period
- [x] End-to-end tests (real TCP client → gateway → upstream)
- [x] Dockerfile (multi-stage, distroless)
- [x] k8s manifests: gateway ×2 replicas + go-httpbin upstream + smoke script
- [x] User-verified: `make minikube-load k8s-deploy smoke` green on local minikube

**Known M1 limitations** (fixed in later milestones): upstream `https://`
targets are accepted by validation but fail at request time — the client has
no TLS connector yet (M7 task). No WebSocket/upgrade passthrough (M8).

## M2 — Auth & key management

- [x] Middleware chain scaffolding: per-API tower stack composed at route-build time (g2-middleware)
- [ ] `KeySession` model (rate, quota, expiry, org_id, per-API access; SHA-256 key hashing)
- [ ] Redis-backed `Storage` implementation (connection pool, `g2:{org}:...` schema) + `make redis-up` integration tests
- [ ] Auth: keyless mode (explicit) and auth-token mode (header/query param/cookie lookup → `KeySession`)
- [ ] Auth: JWT (HS256/RS256, `jwks_url` fetch + cache, claims → session)
- [ ] Auth: basic auth
- [ ] Admin API skeleton (axum on separate port, `X-G2-Authorization` admin secret)
- [ ] Admin key CRUD: `POST/GET/PUT/DELETE /g2/keys[/{key}]`

## M3 — Rate limiting & quotas (distributed)

- [ ] Redis sliding-window rate limiter as an atomic Lua script (`redis::Script`), per-key and per-API
- [ ] Quotas: long-period counters with reset timestamps
- [ ] Local token-bucket spike guard in front of Redis (configurable)
- [ ] 429 responses with `X-RateLimit-Limit/-Remaining/-Reset` headers
- [ ] Multi-pod correctness test documented in smoke script (two replicas share counters)

## M4 — Control plane & hot reload

- [ ] API definitions and policies stored in Redis; file loader becomes one of two sources
- [ ] Policies: reusable rate/quota/ACL bundles referenced by keys
- [ ] Admin CRUD for API definitions and policies
- [ ] `POST /g2/reload` + Redis pub/sub broadcast → every pod rebuilds its route table
- [ ] Dashboard-support API: node info, loaded APIs, health, version, per-API stats snapshot
- [ ] OpenAPI spec for the admin API (utoipa) served at `/g2/openapi.json`

## M5 — Observability

- [ ] OTLP trace export (opentelemetry-otlp) with per-request spans (api_id, key alias, status, upstream latency)
- [ ] OTLP metrics + Prometheus `/metrics` endpoint
- [ ] `AnalyticsSink` trait + per-request analytics records; stdout-JSON, Redis-list, and OTLP-logs sinks
- [ ] deploy/k8s: otel-collector example; document Datadog exporter wiring

## M6 — Traffic middleware

- [ ] Header transforms (add/remove, request and response)
- [ ] URL rewrite (regex) and method transform
- [ ] Mock responses; allow/block/ignore path lists
- [ ] CORS, IP allow/deny lists, request size limits
- [ ] API versioning (header/param selection, per-version overrides)

## M7 — Resilience & upstream management

- [ ] TLS upstream support (hyper-rustls connector) — removes the M1 https limitation
- [ ] Load balancing across multiple upstream targets (round-robin)
- [ ] Upstream health checks with eviction
- [ ] Circuit breaker per route; retries for idempotent methods
- [ ] Response caching (Redis, per-API TTL, safe methods only)

## M8+ — Extended parity (re-prioritize with the user)

- [ ] TLS termination & mTLS client certificates
- [ ] OAuth2/OIDC, HMAC signatures, per-endpoint rate limits
- [ ] WebSocket/SSE passthrough; gRPC passthrough
- [ ] Plugin system (WASM pre/post hooks — needs an ADR first)
- [ ] Service discovery; request/response body transforms

---

## Progress log

- **2026-08-30** — M0 complete; M1 code complete (router, proxy engine, health,
  graceful shutdown, Dockerfile, k8s manifests, 51 tests green). Next: user
  runs `make minikube-load k8s-deploy smoke` on local minikube; then start M2
  (middleware chain scaffolding). Surprise-worthy notes: no `just` on this
  machine → Makefile; local cluster is **minikube** (not k3d/kind); upstream
  client is HTTP-only until the M7 TLS-connector task. Docker Desktop was not
  running (and would not start headlessly), so `docker build` and the
  minikube deploy are still **unverified** — first thing to check next session
  if the user hasn't run `make minikube-load k8s-deploy smoke` yet. The binary
  itself was verified live (health, proxy 200, 404, SIGTERM drain).
- **2026-08-30 (2)** — M1 fully verified: Docker image built, minikube deploy +
  smoke green (2 gateway replicas proxying to go-httpbin). Two deploy fixes:
  `go-httpbin:v2` tag doesn't exist on ghcr → pinned `v2.15.0` (httpbin.yaml +
  Makefile); smoke.sh asserted the scalar query-args shape → now matches the
  echoed URL (v2.15 returns args as arrays). Note: `minikube image load
  g2way:dev` fails with "blob not found" on this Docker Desktop (containerd
  store) — workaround is `docker save` to a tar and `minikube image load
  <tar>`; consider baking that into the Makefile if it recurs. Next: M2
  middleware chain scaffolding (in progress this session).
- **2026-08-30 (3)** — M2 middleware chain scaffolding landed. Each `Route`
  now stores a prebuilt `ChainService` (tower `BoxCloneSyncService`) composed
  at `RouteTable::build(defs, &Forwarder)` time; the forward tail moved out of
  `Gateway::handle` into a `Forward` service (innermost in the chain), the
  hyper client moved into a cheap-clone `Forwarder` handle so pools survive
  reloads, and `Gateway` is de-generified (method-generic `handle<B>` boxes
  bodies at the chain boundary). Proof layers: `SetContextLayer`
  (`RequestContext` extension) + `ApiIdHeaderLayer` (anti-spoof `x-g2-api-id`
  upstream header). **Surprise:** `ProxyBody` had to become a concrete struct
  (axum-style) instead of a `BoxBody` alias — naked `dyn + '_` lifetimes in a
  tower service's request/response types trip rustc's "implementation of
  `tower::Service` is not general enough" (rust-lang/rust#102211) when the
  chain is driven inside a `Send` future; keep body/service type params
  lifetime-free in future layers. Next: M2 `KeySession` model.
