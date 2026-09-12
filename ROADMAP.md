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
- [x] `KeySession` model (rate, quota, expiry, org_id, per-API access; SHA-256 key hashing)
- [x] Redis-backed `Storage` implementation (connection pool, `g2:{org}:...` schema) + `make redis-up` integration tests
- [x] Auth: keyless mode (explicit) and auth-token mode (header/query param/cookie lookup → `KeySession`)
- [x] Auth: JWT with static keys (HS256 secret / RS256 public-key PEM; claims → ephemeral session)
- [ ] Auth: JWT `jwks_url` fetch + cache (needs an HTTPS fetch client — decide alongside the M7 TLS work)
- [x] Auth: basic auth
- [x] Admin API skeleton (axum on separate port, `X-G2-Authorization` admin secret)
- [x] Admin key CRUD: `POST/GET/PUT/DELETE /g2/keys[/{key}]`

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
- [ ] `GET /g2/keys` listing (needs a `Storage::scan`/SCAN operation — deferred from M2 key CRUD)
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
- **2026-08-30 (4)** — M2 `KeySession` model landed in `g2-core::session`:
  idiomatic shapes (`Option<RateLimit>`/`Option<Quota>` instead of
  zero-sentinels; empty `access` map = all APIs in org), with
  `is_expired(now_unix_secs)` (clock passed in, inclusive boundary),
  `allows_api`, SHA-256 `hash_key` (lowercase hex; raw keys never persisted)
  and `session_storage_key` → `g2:{org}:apikey:{hash}`. `ApiAccess` is an
  empty struct on purpose — per-API overrides land with policies (M4) without
  a schema break. Quota counters/reset timestamps deliberately NOT on the
  session — they're live state and belong in storage (M3). Added `sha2`+`hex`
  workspace deps; new `Error::InvalidKeySession`. Next: M2 Redis-backed
  `Storage` (`make redis-up` + integration tests).
- **2026-08-30 (5)** — M2 `RedisStorage` landed (`g2-storage::redis`), built on
  `redis` crate **1.6** (post-1.0 API; `tokio-comp` + `connection-manager`
  features — the manager is one multiplexed auto-reconnecting connection, so
  no separate pool needed; cheap clone). TTLs use `SET … PX` (ms precision;
  sub-ms rounds up to 1ms since PX rejects 0). Integration tests are
  `#[ignore]`d (`make redis-up`, then `cargo test -p g2-storage --
  --ignored`) — **verified green this session** against redis:7-alpine in
  Docker (Docker Desktop working again this session). Gotcha: a crate-root
  `mod redis` shadows the extern crate in `use` paths → use `::redis::…`.
  Next: M2 auth middleware (keyless + auth-token modes).
- **2026-08-30 (6)** — M2 auth landed. `ApiDefinition.auth` is a tagged enum
  (`{"mode":"keyless"}` / `{"mode":"auth_token", header/query_param/cookie}`);
  **default is auth_token on `Authorization`** — keyless must be explicit, so
  a definition missing `auth` is protected, not exposed (examples/apis and the
  k8s configmap now declare keyless; redeploy needed before next smoke).
  `AuthLayer` (g2-middleware) extracts header→query→cookie, strips `Bearer `
  case-insensitively, hashes, looks up `g2:{org}:apikey:{hash}`, checks
  active/expiry/allows_api, stamps `SessionContext` extension; 401 missing,
  403 unknown/inactive/expired/wrong-API (one message, no oracle), 503
  storage down, 500 corrupt record. `RouteTable::build` now takes
  `&SharedStorage` (new alias `Arc<dyn Storage>`); binary grew
  `--redis-url`/`G2_REDIS_URL`/config `redis_url` → RedisStorage, else
  MemoryStorage with a loud warning. `ChainBuilder.auth(Option<AuthLayer>)`
  uses tower's `option_layer`. Next: JWT auth (HS256/RS256 + jwks).
- **2026-08-30 (7)** — M2 JWT auth (static keys) landed; the roadmap's JWT
  task was **split**: `jwks_url` fetch+cache deferred to its own checkbox
  because it needs an HTTPS fetch client (TLS decision otherwise scheduled
  for M7). `AuthConfig::Jwt {signing_method: hs256|rs256, secret |
  public_key_pem, header, identity_claim (default "sub")}`; validation
  rejects mismatched key material. Verification synthesizes an ephemeral
  `KeySession` (alias = identity claim, `expires_at` = `exp` — required,
  access = this API only), no storage lookup; virtual rate-limit identity is
  `hash_key("jwt:{identity}")` to avoid colliding with stored-token hashes.
  Alg-confusion (HS256 token on RS256 API) tested-rejected. **Gotcha:**
  `jsonwebtoken` 10 panics at runtime without a crypto-provider feature —
  workspace dep pins `features = ["rust_crypto"]` (pure Rust, distroless-
  friendly). Next: basic auth, then admin API skeleton.
- **2026-08-30 (8)** — M2 basic auth landed. `{"mode":"basic_auth", realm?}`
  (default realm `g2way`); credentials only from `Authorization: Basic …`
  (RFC 7617 — no query/cookie carriers, they'd leak passwords into logs).
  `KeySession` gained `basic_auth: Option<BasicAuthData{password_hash}>`
  (bcrypt string; old records deserialize unchanged); session stored under
  `hash_key("basic:{username}")` — same `apikey` Redis kind, namespaced like
  `jwt:`. Deliberate hardening choices: 401 (+`WWW-Authenticate` challenge)
  **only** for unparseable credentials; wrong password is 403 with the shared
  no-oracle message like every other rejection. Unknown users still cost one
  bcrypt verify against an embedded dummy hash (no user-enumeration timing
  oracle). Verify runs in `spawn_blocking` (bcrypt ~100–250ms at cost 12
  would stall a worker); per-user verify caching deliberately deferred —
  revisit if basic-auth traffic matters. New workspace deps: `bcrypt` 0.17,
  `base64` 0.22 (both pure Rust); g2-middleware's `tokio` moved dev→real dep.
  Next: admin API skeleton (axum, separate port, `X-G2-Authorization`).
- **2026-08-30 (9)** — M2 admin API skeleton landed (`g2-admin`, axum 0.8 on
  its **own listener**). Enabled only when `admin_listen_addr` is configured
  (`--admin-listen`/`G2_ADMIN_LISTEN`), and `GatewayConfig::validate()` (new)
  hard-fails startup if the listener is set without a non-empty
  `admin_secret` (`--admin-secret`/`G2_ADMIN_SECRET`, hidden from `--help`
  env display) — never unsecured. Secret checked by comparing SHA-256
  digests (timing-safe enough: digest comparison leaks nothing about the
  secret). Missing and wrong secret are one 403 message; the authed
  router's *fallback* is behind the auth layer too, so unknown admin paths
  read 403 to outsiders and 404 only with the secret. `/g2/health` is
  unauthenticated (probes); `/g2/version` authed. Binary now fans one
  SIGTERM/SIGINT out to both listeners via a `tokio::sync::watch` channel and
  `try_join!`s the two serve loops. Verified live: 403/200/graceful-drain on
  a local run. New `Error::InvalidGatewayConfig`. deploy/k8s deliberately
  untouched until key CRUD makes the admin port useful. Next: admin key CRUD
  (`/g2/keys`).
- **2026-08-30 (10)** — M2 admin key CRUD landed (`g2-admin::keys`), closing
  M2 except the deferred `jwks_url` task. `POST /g2/keys` generates the raw
  key server-side (32 random bytes, hex; `rand` 0.9 workspace dep) and
  returns it **once** — storage only ever holds the SHA-256. `GET/PUT/DELETE
  /g2/keys/{key}` address by raw key, or by hash with `?hashed=true` (the
  only handle left after creation); `GET`/`DELETE` take `?org_id=`
  (default org), `POST`/`PUT` read org from the session body. Sessions are
  `validate()`d → 400 with reason; storage errors → 503; corrupt records →
  500. `PUT /g2/keys/basic:alice` provisions basic-auth users (same virtual-
  key namespace the auth middleware reads — tested). Listing deferred to a
  new M4 checkbox (needs `Storage::scan`). No session TTLs written yet
  (auth already enforces `expires_at`; storage-side GC is a possible M3+
  optimization). Verified live end-to-end: POST key → 401/403/passed-auth on
  the proxy → DELETE → 403. Next: M3 Redis sliding-window rate limiter
  (Lua), or revisit deferred `jwks_url` when M7 TLS lands.
