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

**Known M1 limitations**: upstream `https://` targets — fixed by the M7
TLS connector (hyper-rustls). No WebSocket/upgrade passthrough yet (M8).

## M2 — Auth & key management

- [x] Middleware chain scaffolding: per-API tower stack composed at route-build time (g2-middleware)
- [x] `KeySession` model (rate, quota, expiry, org_id, per-API access; SHA-256 key hashing)
- [x] Redis-backed `Storage` implementation (connection pool, `g2:{org}:...` schema) + `make redis-up` integration tests
- [x] Auth: keyless mode (explicit) and auth-token mode (header/query param/cookie lookup → `KeySession`)
- [x] Auth: JWT with static keys (HS256 secret / RS256 public-key PEM; claims → ephemeral session)
- [x] Auth: JWT `jwks_url` fetch + cache (client: the proxy's shared hyper-rustls client behind a `JwksFetch` trait; pod-local ArcSwap cache, periodic + on-miss refresh, stale-on-error)
- [x] Auth: basic auth
- [x] Admin API skeleton (axum on separate port, `X-G2-Authorization` admin secret)
- [x] Admin key CRUD: `POST/GET/PUT/DELETE /g2/keys[/{key}]`

## M3 — Rate limiting & quotas (distributed)

- [x] Redis sliding-window rate limiter as an atomic Lua script (`redis::Script`), per-key and per-API
- [x] Quotas: long-period counters with reset timestamps
- [x] Local token-bucket spike guard in front of Redis (configurable)
- [x] 429 responses with `X-RateLimit-Limit/-Remaining/-Reset` headers
- [x] Multi-pod correctness test documented in smoke script (two replicas share counters)

## M4 — Control plane & hot reload

- [x] API definitions stored in Redis; file loader becomes one of two sources (ADR-0002; policy records follow with the policy model below)
- [x] Policies: reusable rate/quota/ACL bundles referenced by keys
- [x] Admin CRUD for API definitions and policies (`/g2/apis`, `/g2/policies`)
- [x] `GET /g2/keys` listing (needs a `Storage::scan`/SCAN operation — deferred from M2 key CRUD)
- [x] `POST /g2/reload` + Redis pub/sub broadcast → every pod rebuilds its route table
- [x] Dashboard-support API: node info, loaded APIs, health, version, per-API stats snapshot
- [x] OpenAPI spec for the admin API (utoipa) served at `/g2/openapi.json`

## M5 — Observability

- [x] OTLP trace export (opentelemetry-otlp) with per-request spans (api_id, key alias, status, upstream latency)
- [x] OTLP metrics + Prometheus `/metrics` endpoint
- [x] `AnalyticsSink` trait + per-request analytics records; stdout-JSON, Redis-list, and OTLP-logs sinks
- [x] deploy/k8s: otel-collector example; document Datadog exporter wiring

## M6 — Traffic middleware

- [x] Header transforms (add/remove, request and response)
- [x] URL rewrite (regex) and method transform
- [x] Mock responses; allow/block/ignore path lists
- [x] CORS, IP allow/deny lists, request size limits
- [x] API versioning (header/param selection, per-version overrides)

## M7 — Resilience & upstream management

- [x] TLS upstream support (hyper-rustls connector) — removes the M1 https limitation
- [x] Load balancing across multiple upstream targets (round-robin)
- [x] Upstream health checks with eviction
- [x] Circuit breaker per route; retries for idempotent methods
- [x] Response caching (Redis, per-API TTL, safe methods only)

## M8+ — Extended parity (re-prioritize with the user)

- [x] TLS termination & mTLS client certificates (ADR-0003, `docs/tls.md`)
- [x] OAuth2/OIDC: external-IdP token validation (discovery + JWKS,
      iss/aud checks, client-id→policy mapping; `docs/oidc.md`)
- [x] HMAC request signatures (draft-cavage, `docs/hmac.md`)
- [x] Per-endpoint rate limits (aggregate, API-level; `docs/endpoint-rate-limits.md`)
- [x] WebSocket/SSE passthrough (`Connection: Upgrade` tunneling via per-API
      `enable_upgrades`; `docs/websockets.md`)
- [x] gRPC passthrough (end-to-end HTTP/2 via per-API `upstream_http2`:
      h2c/ALPN upstream client + trailer forwarding; `docs/grpc.md`)
- [x] Plugin system (WASM pre/post hooks — wasmtime, custom JSON ABI;
      ADR-0005, `docs/plugins.md`)
- [x] Service discovery (HTTP+JSON polling of a catalog endpoint;
      live target swaps via ArcSwap — ADR-0006, `docs/service-discovery.md`)
- [x] Request/response body transforms (minijinja templates, endpoint-scoped
      rules — ADR-0007, `docs/body-transforms.md`)

## M9 — GraphQL

- [x] GraphQL proxy mode + protections: per-API `graphql` block (SDL schema in the
      definition), request parse/validation against the schema, depth limits,
      introspection control, per-key field permissions (`allowed_types`/
      `restricted_types`) and key-level depth/introspection overrides
      (ADR-0004, `docs/graphql.md`)
- [x] GraphQL playground served per API (behind the API's auth chain)
- [x] Persisted GraphQL-as-REST endpoints (method/path → operation, variable
      substitution from headers and path params)
- [x] Schema sync from upstream introspection (admin-triggered + periodic;
      ADR-0008, `docs/graphql.md` §Schema sync)
- [x] GraphQL subscriptions over WebSocket (terminate-and-police relay,
      both subprotocols — ADR-0009, `docs/graphql.md` §Subscriptions)
- [x] Universal Data Graph: gateway-executed stitching of REST/GraphQL upstreams
      (root-field data sources, minijinja templates — ADR-0010,
      `docs/graphql.md` §Universal Data Graph)
- [x] Federation: supergraph/subgraph support (`subgraph` + `supergraph`
      execution modes: gateway-side composition and `_entities` execution —
      ADR-0011, `docs/graphql.md` §Federation)
- [ ] GraphQL-aware response caching
- [ ] Stretch: query complexity/cost limits; automatic persisted
      queries (APQ)

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
- **2026-08-30 (11)** — M3 sliding-window rate limiter landed as a `Storage`
  trait method: `check_rate(key, limit, window) -> RateDecision {allowed,
  remaining, reset_after}` — sliding-window **log** (no boundary bursts),
  denied requests consume no slot, limit 0 denies all. Redis impl is one
  atomic `redis::Script` over a sorted set (ZREMRANGEBYSCORE→ZCARD→ZADD→
  PEXPIRE) that reads the **Redis server clock** (`TIME`) so pods need no
  clock sync; a random `u64` member suffix keeps same-millisecond requests
  distinct. Verified against real Redis incl. 20-concurrent-checks-admit-
  exactly-5 atomicity test. Memory impl mirrors semantics on `tokio::time`
  (pause/advance in tests). The limiter is a primitive — nothing calls it
  yet; identity composition (`{key_hash}` vs per-API) and 429s land with
  the middleware checkbox. Note: `make redis-up` errors if the container
  already exists from a prior run — harmless, but worth an idempotency fix
  someday. Next: quota counters (long-period, reset timestamps).
- **2026-08-30 (12)** — M3 quota counters landed: `Storage::check_quota(key,
  max, period)` — **fixed-period** (the period starts at the
  first request, whole allowance renews at once; deliberately not sliding
  like `check_rate`). Redis impl is a second Lua script: INCR + PEXPIRE-on-
  first + PTTL-as-reset, with a defensive re-expire if a counter ever loses
  its TTL (can't deny forever). `RateDecision` renamed → `LimitDecision`,
  shared by both checks (same shape). Denied requests still INCR (harmless
  over max, never extends the period). Verified against real Redis (renewal
  + 20-concurrent-admit-exactly-5). Next: local token-bucket spike guard in
  front of Redis.
- **2026-08-30 (13)** — M3 spike guard landed (`g2-middleware::spike`): a
  pod-local, **lock-free** token bucket (packed `AtomicU64` CAS loop —
  hi 32 = last-refill secs since guard epoch, lo 32 = tokens) sharded into a
  fixed 4096-bucket array by identity hash — collisions only ever make the
  guard stricter. Whole-second refill; the refill timestamp advances **only
  when credit lands** (else constant sub-second traffic would starve refill
  — tested). Config: `GatewayConfig.spike_guard: Option<{capacity,
  refill_per_sec}>` (None = off; zeros rejected by validate()). Not yet
  consulted anywhere — it fronts Redis inside the rate-limit middleware,
  which is the next checkbox (429 + X-RateLimit headers) and will also pick
  the guarded identity. 8-thread × 50-acquire test proves exactly-capacity
  admissions. Next: 429 middleware wiring rate+quota+spike into the chain.
- **2026-08-30 (14)** — M3 rate-limit middleware landed
  (`g2-middleware::rate_limit`): `RateLimitLayer` sits after auth, reads the
  `SessionContext`, and enforces cheapest-first: spike guard (local 429) →
  `check_rate` (429) → `check_quota` (**403** "quota exceeded";
  waiting won't help). Headers on every denial: `X-RateLimit-Limit/
  -Remaining/-Reset` (Reset = absolute Unix secs) + `Retry-After`
  (ceil, ≥1s). Counters are **per key across APIs** by default:
  `g2:{org}:ratelimit:{key_hash}` / `g2:{org}:quota:{key_hash}` (helpers in
  g2-core::session). Storage errors **fail open** (loudly logged): limits
  protect capacity, and token/basic auth already fail closed upstream in the
  chain — only JWT traffic is affected by a Redis outage, and it keeps
  serving. Keyless APIs get no limiter (no session). `RouteTable::build`
  grew a `spike_guard: Option<&Arc<SpikeGuard>>` param; binary builds the
  guard from config. Rate-denied requests don't consume quota (checked in
  that order). A rate-allowed-but-quota-denied request does occupy a rate
  slot — acceptable. Next: M3 multi-pod smoke (needs Redis in
  deploy/k8s + smoke.sh assertions).
- **2026-08-30 (15)** — **M3 complete.** Multi-pod rate-limit smoke landed:
  new `deploy/k8s/redis.yaml` (redis:7-alpine, no persistence), gateway
  Deployment gained `G2_REDIS_URL`/`G2_ADMIN_LISTEN=0.0.0.0:9696`/
  `G2_ADMIN_SECRET` (dev-only literal in the manifest) + `admin`
  containerPort, and the ConfigMap gained a second, auth_token API
  (`/limited/` → httpbin) because keyless APIs never get a `RateLimitLayer`.
  smoke.sh now port-forwards **each pod individually** (a Service
  port-forward pins to one pod), provisions a rate-5/60s key via `PUT
  /g2/keys/{key}` (chosen raw key per run → no jq; unique per run so stale
  sliding windows can't skew counts), alternates 6 requests A,B,A,B,A,B and
  asserts request 6 is 429 with correct `X-RateLimit-*`/`Retry-After` —
  per-pod counters would have allowed it, and fail-open on storage errors
  means a broken Redis wiring also fails the 429 assertion. **Verified green
  on minikube end to end.** The session-2 `minikube image load` "blob not
  found" issue recurred → Makefile `minikube-load` now goes through `docker
  save` to a tar as that log suggested. Next: M4 (API definitions/policies
  in Redis; file loader becomes one of two sources).
- **2026-08-30 (16)** — M4 storage-backed definition source landed, with
  **ADR-0002** (read it before the remaining M4 tasks — it fixes the key
  schema, merge semantics, and reload consequences). JSON `ApiDefinition`
  records live at `g2:{org}:apidef:{api_id}` (helpers in
  `g2_core::api_definition`), enumerated via new trait op
  `Storage::scan_prefix` (Redis SCAN+MATCH with glob-escaped prefix, deduped;
  this also unblocks the deferred `GET /g2/keys` listing checkbox).
  `g2_storage::load_api_definitions` scans/parses/validates (corrupt record
  = load fails loudly; record must round-trip its own storage key);
  `g2_core::loader::merge_sources` combines file+storage sets — duplicate
  api_id/listen_path across or within sources errors naming both sources, no
  precedence. Verified live: seeded def in Redis routed next to the file
  def, and a cross-source duplicate refused startup. The checkbox's
  "policies" half deliberately waits for the policy model (next task).
  `make redis-up` is now idempotent (`docker start ||` fallback — the
  session-11 nit). Note: nothing writes defs to Redis yet; admin CRUD is
  two checkboxes away. Next: M4 policies (rate/quota/ACL bundles).
- **2026-08-30 (17)** — M4 policies landed. `Policy` (g2-core::policy):
  policy_id/name/org_id/active/rate/quota/access, JSON at
  `g2:{org}:policy:{id}`. `KeySession.apply_policies: Vec<String>` (a list
  for forward compatibility; old records deserialize) — **validate() caps
  it at one** because combining needs partitioned policies (a later
  refinement if wanted). Semantics: non-partitioned — the policy's
  rate/quota/access **replace** the session's wholesale
  (`KeySession::apply_policy`); expires_at/active/alias/basic_auth stay
  per-key. Auth middleware resolves the policy after per-key active/expiry
  checks but **before** `allows_api` (the policy ACL can grant *or* revoke):
  missing or inactive policy → no-oracle 403 (logged; inactive = tier kill
  switch, verified live), corrupt/misfiled/multi-policy record → 500,
  storage error → 503. One extra storage GET per request only for keys
  referencing a policy; a session/policy read-through cache is a noted
  future optimization. JWT sessions are ephemeral and never carry policies.
  Verified live on Redis: key with `apply_policies:["free"]` and no own
  rate got 429'd at the policy's 2/60 with correct headers. Policy admin
  CRUD is deliberately the next-but-one checkbox (defs CRUD first). Next:
  M4 admin CRUD for API definitions and policies.
- **2026-08-30 (18)** — M4 admin CRUD for API definitions and policies
  landed: `/g2/apis` and `/g2/policies` (GET list / POST create /
  GET/PUT/DELETE by id). Both are one generic
  handler set (`g2-admin::resources`, `StoredResource` trait supplies key
  schema + validation) — a third resource kind costs one trait impl. POST
  of an existing id = 409 (PUT is the overwrite path); PUT body-id ≠
  path-id = 400; list uses `scan_prefix` and returns full records sorted
  by id. **Writes do not touch the running route table** (by design):
  verified live — POST def → listed + in Redis + 409 on dup, 404 on the
  proxy until a restart picked it up, then 200. Cross-source conflicts
  (admin def vs file def) surface at load/reload per ADR-0002, not at
  write time — the reload task should surface that error to the caller.
  Next: M4 `GET /g2/keys` listing (trivial now with scan_prefix), then
  `POST /g2/reload` + pub/sub.
- **2026-08-30 (19)** — M4 `GET /g2/keys` listing landed (the M2 deferral):
  returns `{"keys": [<hash>, …]}` sorted, per-org via `?org_id=`, hashes
  only (raw keys unrecoverable by design). New
  `session_key_prefix` helper in g2-core. Next: M4 `POST /g2/reload` +
  Redis pub/sub broadcast so admin def/policy writes go live without a
  restart (the biggest remaining M4 piece — needs an in-process rebuild
  path from `SharedStorage` + file defs to a new `RouteTable`, an ArcSwap
  store the binary already has, and a subscriber task per pod).
- **2026-08-30 (20)** — M4 hot reload landed. `Storage` grew fire-and-forget
  pub/sub: `publish(channel, payload)` + `subscribe(channel) ->
  mpsc::Receiver<String>` (best-effort delivery; payloads must be
  re-derivable from storage). Redis impl keeps the `Client` and dials a
  dedicated pub/sub connection per subscription inside a re-dial-with-
  backoff task (new `futures-util` workspace dep for `StreamExt`); memory
  impl is per-channel `tokio::broadcast` bridged to mpsc. `POST /g2/reload`
  (admin) publishes to `g2:{org}:channel:reload`
  (`g2_core::config::reload_channel`) and returns immediately; each pod's
  `g2way::reload::listen` task (new module; `ReloadContext.build_table()`
  is now the one files+storage→RouteTable path, also used at startup)
  rebuilds and `Gateway::reload`-swaps — a failed rebuild logs and keeps
  the old table (tested, incl. listener surviving the failure). **Verified
  live: two gateway processes sharing Redis; def POSTed via admin on pod A
  + one reload → both pods 404→200 with "route table reloaded" in both
  logs, no restarts.** Note: deploy/k8s smoke not extended for reload yet —
  worth folding into the dashboard-support-API task's smoke pass. Next:
  M4 dashboard-support API (node info, loaded APIs, health, version,
  per-API stats snapshot).
- **2026-08-30 (21)** — M4 dashboard-support API landed: `GET /g2/node`
  (node_id from `$HOSTNAME` — k8s pod name, null bare; version; uptime;
  APIs currently routed, straight from the live table so hot reloads show
  immediately, each with auth_mode via new `AuthConfig::mode_name`) and
  `GET /g2/stats` (per-API requests + status-class counters). Counters:
  new `g2-middleware::stats` — `StatsLayer` outermost in every chain
  (rejections count too), atomics in a process-wide `StatsRegistry` keyed
  by api_id so counters survive reloads (verified live) but reset on
  restart; cluster-wide durable analytics stay an M5 concern.
  `RouteTable::build` grew a 5th param `Option<&Arc<StatsRegistry>>`;
  `g2_admin::router` grew `Option<Dashboard>` (503s from the two endpoints
  when absent; binary always wires it; g2-admin now deps g2-proxy +
  g2-middleware). Health/version halves of the checkbox existed since the
  M2 skeleton. Verified live: 3×2xx+1×5xx counted, node lists the API.
  Next: M4's last box — OpenAPI spec (utoipa) at `/g2/openapi.json`.
- **2026-08-30 (22)** — **M4 complete.** OpenAPI spec landed: utoipa 5,
  `GET /g2/openapi.json` (authenticated like the rest). g2-core grew an
  `openapi` feature gating `ToSchema` derives on the 9 JSON models (keeps
  utoipa out of the proxy path's dependency tree; g2-admin enables it).
  `#[utoipa::path]` annotations are colocated with every handler; the
  generic resource CRUD gets concrete annotated bindings (`list_apis` …
  `delete_policy` in resources.rs) because the macro describes exactly one
  path. `admin_secret` security scheme = `X-G2-Authorization` API-key
  header. A unit test asserts every mounted route and core schema appears
  in the document, so an undocumented new route fails `make check`.
  Verified live: 3.1.0 doc, 11 paths, 9 schemas. **All of M4 done in one
  session (entries 16–22).** Not done anywhere yet: k8s smoke has no
  reload/dashboard assertions (deploy/k8s unchanged since M3 — still
  applies cleanly). Next milestone: M5 observability (OTLP traces first);
  the deferred M2 `jwks_url` box still waits on the M7 TLS decision.
- **2026-08-31** — M5 OTLP trace export landed. Transport is deliberately
  OTLP over **HTTP/protobuf** (`{endpoint}/v1/traces`, port 4318) with
  `reqwest-blocking-client` on the SDK's own batch thread — the grpc-tonic
  exporter needs a tokio runtime handle, this one works before the runtime
  starts and after it stops (telemetry now inits inside `run()` after
  config merge; startup errors print via `eprintln!` since they can predate
  the subscriber; `TelemetryGuard::shutdown()` flushes last). Spans come
  from a new always-on `TraceLayer` (g2-middleware, outermost in every
  chain) bridged via `tracing-opentelemetry`: name = listen path, fields
  `api_id`/`org_id`/`http.request.method`/`url.path`/
  `http.response.status_code` + `otel.status_code=ERROR` on 5xx only;
  auth records `key_alias` and the forwarder records `upstream_latency_ms`
  through `tracing::Span::current()` (no-ops when unexported). Spans also
  enrich JSON logs (fmt layer has `with_current_span`); they're info-level,
  so `RUST_LOG=warn` disables export. Config: `otlp_endpoint` /
  `--otlp-endpoint` / `G2_OTLP_ENDPOINT`; resource carries service
  name/version + `host.name` from `$HOSTNAME`. Non-ignored unit test runs a
  fake one-shot collector (std TcpListener); **verified live**: real
  gateway run exported protobuf spans carrying every field above. Health
  endpoints/404s produce no span (no chain). Deps: opentelemetry 0.32 +
  tracing-opentelemetry 0.33. Follow-ups noted: W3C `traceparent`
  extract/inject (context propagation to upstreams) deliberately not in
  this checkbox — decide when wiring the collector example; no span for
  the admin API. Next: OTLP metrics + Prometheus `/metrics`.
- **2026-08-31 (2)** — M5 metrics landed: one `SdkMeterProvider`, two
  readers over the same instruments — periodic OTLP push (HTTP/protobuf to
  `{otlp_endpoint}/v1/metrics`, same endpoint/knob and same no-tokio design
  as traces) and a Prometheus pull reader (`opentelemetry-prometheus` 0.32,
  which resumed maintenance and matches our 0.32 pin) rendered by
  **unauthenticated** `GET /metrics` on the admin listener (scrapers can't
  send custom headers; the admin port stays cluster-internal). **No new
  config**: OTLP metrics ride `otlp_endpoint`, Prometheus is on iff the
  admin listener is. Instrumentation is one semconv histogram —
  `http.server.request.duration` (seconds, explicit semconv buckets; SDK
  defaults are ms-tuned garbage for seconds) with `http.route`/
  `http.response.status_code`/`g2.api_id`/`g2.org_id` — recorded by a new
  `MetricsLayer` between trace and stats; per-API attrs are precomputed
  Arc-backed `KeyValue`s (hot-path rule), instruments are created **once
  per process** (`HttpMetrics::new()` after the global provider install —
  earlier binds to the no-op provider and silently drops everything) and
  shared via `ReloadContext.metrics`; `RouteTable::build` grew a 6th
  `Option` param. Keyless APIs are measured (unlike rate limiting);
  health/404s aren't (no chain). `init_telemetry` gained a `prometheus:
  bool` and the guard now carries both providers + a `PrometheusHandle`.
  Verified live: 3×200+1×404 showed as labeled histogram count/sum via
  curl `/metrics` (no secret), and a fake collector received both
  `POST /v1/traces` and `POST /v1/metrics` on SIGTERM flush (steady-state
  push is the 60s default period). Not done: k8s Prometheus scrape
  annotations / otel-collector example — that's the M5 deploy checkbox.
  Next: `AnalyticsSink` trait + per-request analytics records.
- **2026-08-31 (3)** — M5 analytics landed. `AnalyticsRecord` (g2-core, JSON
  wire shape, optionals omitted/tolerated for schema growth) is produced by
  a new `AnalyticsLayer` sitting **above auth** (rejections are traffic
  too), which therefore reads session identity and upstream latency from
  **response extensions**: auth now stamps `SessionContext` and the
  forwarder a new `UpstreamLatency` onto every response — the pattern for
  any future outer layer needing inner-layer facts. Hand-off is a bounded
  `try_send` (`AnalyticsHandle`, cap 8192; full channel drops + counts,
  never blocks); one process-wide worker (`g2_telemetry::analytics::run`)
  batches (512/1s) into an `AnalyticsSink`: `stdout` (JSON lines),
  `redis` (`Storage` grew `list_append`/`list_drain` — RPUSH+LTRIM capped
  at 100k/org at `g2:{org}:analytics:records`, LPOP for a future pump),
  `otlp_logs` (`/v1/logs`, JSON body + api/org/status attrs, same no-tokio
  batch design). Config `analytics_sink` / `--analytics-sink` /
  `G2_ANALYTICS_SINK`; validate() requires redis_url / otlp_endpoint for
  the matching sinks. Binary stops the worker **after** listener drain, so
  in-flight records flush before exit. `RouteTable::build` grew a 7th
  `Option` param — that signature now really wants a params-struct
  refactor next time it grows. Verified live: stdout + redis sinks end to
  end (alias/hash on authed records, 401/403 recorded bare); otlp_logs via
  fake-collector unit test; redis `--ignored` suite green. Next: M5 deploy
  checkbox (otel-collector example + Datadog wiring docs), which should
  also pick up the deferred k8s smoke gaps (reload/dashboard assertions,
  Prometheus scrape annotations).
- **2026-08-31 (4)** — **M5 complete** (minus the M2 `jwks_url` deferral,
  which waits on M7 TLS). Deploy checkbox landed: `deploy/k8s/
  otel-collector.yaml` (contrib 0.115.1 image — the core distribution has
  no datadog exporter — OTLP HTTP 4318, debug exporter on all three
  pipelines, Datadog blocks present-but-commented); gateway Deployment
  gained `G2_OTLP_ENDPOINT` → collector, `G2_ANALYTICS_SINK=otlp_logs`,
  and `prometheus.io/*` pod annotations; `docs/observability.md`
  documents the knobs + two Datadog paths (collector datadog exporter /
  DD Agent OTLP ingest). smoke.sh picked up every deferred gap: dashboard
  (`/g2/node` + `/g2/stats`), unauthenticated `/metrics` histogram,
  full hot-reload round-trip (admin PUT def → 404 → `/g2/reload` → 200 on
  **both** pods → DELETE → reload → 404; unique listen path per run,
  fixed api_id so PUT self-heals leftovers), and traces arriving in
  collector logs (polls ~30s; metrics ride a 60s push period so smoke
  only asserts traces). **Verified green on minikube end to end**, and
  all three signals (Traces/Metrics/Logs) confirmed in collector logs
  manually. Next: M6 traffic middleware, first box: header transforms
  (add/remove, request and response).
- **2026-08-31 (5)** — M6 header transforms landed. `ApiDefinition` grew
  `transform_headers: Option<HeaderTransforms>` (new `g2-core::transform`
  module: `{request, response}` × `{add: map, remove: list}`; remove runs
  before add, add **replaces** existing values; validation rejects bad
  names/values and hop-by-hop headers in `add` — removing them stays
  allowed). Runtime is `HeaderTransformLayer` (g2-middleware): string
  config precompiled to `HeaderName`/`HeaderValue` at route-build time
  (hot path only does Bytes-cheap remove/insert). Chain position: **below
  auth/rate-limit** (gateway 401/403/429 rejections untransformed by
  design; forwarder 502/504 do get response transforms) and **above**
  `ApiIdHeaderLayer`, so a transform can never spoof `x-g2-api-id`
  (tested). New schemas registered in the OpenAPI doc. All unit-level
  (chain + layer tests); no e2e/smoke change. Next: M6 URL rewrite
  (regex) and method transform.
- **2026-08-31 (6)** — M6 URL rewrite + method transform landed. Config in
  `g2-core::transform`: `ApiDefinition.url_rewrites: Vec<UrlRewriteRule>`
  (`{pattern, rewrite}`, first match wins) and `transform_method:
  Option<String>` (standard methods minus CONNECT, case-insensitive).
  **Not a tower layer** — deliberately implemented in the forwarder
  (`g2-proxy::rewrite`, which already owns all upstream-URL computation):
  a layer above the forwarder would fight the listen-path strip that
  happens inside it. Semantics: pattern is regex-searched (unanchored)
  against the **full client path** (listen path included);
  the expansion (`$1`/`${name}` via `Captures::expand`) replaces the
  strip step and is joined onto the target base path like a stripped
  tail; it may carry its own query, which precedes the client's
  (`?rw&client`). Regexes compile once at route build
  (`UpstreamTarget::build` — no route-table signature change), so the
  hot path only runs prebuilt automata (regex crate = linear-time, no
  ReDoS). Method override swaps the verb at forward time only: client-
  facing telemetry/analytics keep reporting the original method, body
  forwarded unchanged. New workspace dep `regex` (g2-core validation +
  g2-proxy). e2e test drives both through a real gateway. Next: M6 mock
  responses; allow/block/ignore path lists.
- **2026-08-31 (7)** — M6 path lists + mock responses landed. Config in new
  `g2-core::endpoints`: `ApiDefinition.{allow,block,ignore_auth}_paths:
  Vec<PathRule{pattern, methods}>` and `mock_responses: Vec<MockResponse
  {pattern, methods, status=200, body, headers}>` — patterns regex-searched
  against the full client path like `url_rewrites`; empty `methods` = all;
  mock headers reject hop-by-hop, no content-type implied. Runtime is two
  layers: `PathPolicyLayer` **above auth** (block → 403; non-empty allow
  list → 403 for non-matches, one shared no-oracle message; ignore match
  stamps a new `AuthBypass` request extension that auth honors — no session,
  so rate limiting skips too) and `MockResponseLayer` **below
  auth/rate-limit/header-transforms** (protected API ⇒ protected mocks,
  consuming rate; mock responses get response transforms; first match wins;
  precompiled regex/StatusCode/HeaderValue/Bytes). **Deliberate deviation
  from the obvious order:** block beats ignore — a blocked
  path stays blocked even if also ignored/allowed, and ignored paths must
  still pass the allow list (ignore = skip auth only, not access control).
  Both layers `from_config → Ok(None)` when unconfigured (chain unchanged
  for existing APIs). New OpenAPI schemas registered + asserted; e2e test
  drives ignored-mock/blocked/still-authed paths through a real gateway.
  g2-middleware gained the `regex` workspace dep. Next: M6 CORS, IP
  allow/deny lists, request size limits.
- **2026-08-31 (8)** — M6 CORS + IP lists + request size limits landed.
  Config in new `g2-core::security`: `ApiDefinition.cors:
  Option<CorsConfig>` (origins/methods/headers/expose/credentials/max-age/
  `options_passthrough`; validation rejects `*`+credentials and `*` mixed
  with explicit origins; empty `allowed_headers` = mirror the preflight's
  request), `allow_ips`/`block_ips: Vec<String>` (IP or CIDR — new
  workspace dep `ipnet`), `max_request_body_bytes: Option<u64>`. Three new
  layers, all **above auth**, outermost first: `IpFilterLayer` (socket
  peer address only — **never** X-Forwarded-For, spoofable; fails closed
  on a missing `ClientAddr`; `to_canonical()` so v4-mapped v6 peers match
  v4 rules; block wins, non-empty allow = allow-list-only, one 403
  message), `CorsLayer` (answers preflights gateway-side so they need no
  credentials, decorates all responses incl. 401/403/429 so browsers can
  read them; disallowed origins still proxied without CORS headers — CORS
  is not access control), `RequestSizeLimitLayer` (two-tier:
  Content-Length over limit → 413 up front; a counting body wrapper fails
  chunked/h2 streams mid-send with a `RequestTooLarge` the **forwarder
  downcasts** out of the hyper error chain → 413, not a bogus 502 —
  e2e-tested). **Surprise:** Xcode 26's ld asserts (`name.size() <=
  maxLength`) on the legacy-mangled symbols of the now-14-layer tower
  chain type — fixed by workspace `.cargo/config.toml` setting
  `-Csymbol-mangling-version=v0` (back-references compress the nested
  types; zero runtime cost; a RUSTFLAGS env var would override it). Next:
  M6's last box — API versioning (header/param selection, per-version
  overrides).
- **2026-08-31 (9)** — **M6 complete.** API versioning landed. Config in new
  `g2-core::versioning`: `ApiDefinition.versioning: Option<VersioningConfig>`
  — `location` header (default) or query_param, `key` (default
  `x-api-version`), optional `default_version`, `versions: {name →
  VersionOverrides}`. Overrides replace the base field **wholesale** (policy
  semantics; `[]` clears a list, `Option` base fields can't be cleared per
  version): `target_url`, `upstream_timeout_ms`,
  `transform_headers`, `url_rewrites`, `transform_method`, the three path
  lists, `mock_responses`, plus `expires_at` (unix secs, inclusive like
  sessions). Validation builds every effective per-version definition and
  re-validates it, prefixing errors with the version name. Runtime: each
  version gets its own **full inner chain + forwarder target** built from
  its effective definition; a `VersionDispatch` service (g2-middleware)
  selects by trimmed header/param value, falls back to the default, and
  403s no-version/unknown/expired. `ChainBuilder` split for
  this: `build_outer` (trace→CORS + context stamp, shared across versions)
  and `build_inner` (path-policy→api-id header, per version) alongside the
  unchanged `build`; the split point is **below CORS**, so version 403s are
  still counted/recorded/CORS-decorated, and **above path_policy**, since
  path lists are per-version. Router grew a shared `inner_layers()` helper
  (one place configures the inner half for both paths). New OpenAPI schemas
  registered. e2e test drives default/override/expired/unknown through a
  real gateway. Not done (deliberate): version-in-URL selection (first path
  segment) and stripping the version data from the upstream request; per-version key ACLs wait for the
  partitioned-policy refinement. Next milestone: M7 resilience — first box
  TLS upstream support (hyper-rustls), which also unblocks the deferred M2
  `jwks_url` task.
- **2026-08-31 (10)** — M7 TLS upstream support landed. `Forwarder`'s client
  is now `Client<HttpsConnector<HttpConnector>>` (hyper-rustls 0.27,
  `https_or_http` + `enable_http1`): one pooled client serves both schemes,
  no signature changes anywhere — plain-http APIs are untouched. Crypto
  provider is **ring** across the tree (workspace pins
  `default-features = false` on rustls/hyper-rustls/tokio-rustls/rcgen)
  because the default aws-lc-rs needs cmake, which the `rust:1-slim` Docker
  build stage doesn't have. Roots: platform CA store (rustls-native-certs),
  falling back to embedded webpki (Mozilla) roots with a warning —
  distroless/cc carries `/etc/ssl/certs`, so the shipped image uses native.
  New public `Forwarder::with_tls_config(rustls::ClientConfig)` for custom
  CAs; it's also how tests inject trust: unit tests run a real tokio-rustls
  upstream with an rcgen self-signed cert and prove trusted-root → 200
  (body verified) and default forwarder → 502 (verification actually on).
  Verified live: gateway proxied `/tlslive/` → `https://httpbingo.org`,
  200 with query + XFF intact. The M2 `jwks_url` deferral is now unblocked
  (rustls in tree; remaining decision is just the fetch client — reusing
  the hyper client vs a one-shot request helper). Next: M7 load balancing
  across multiple upstream targets (round-robin).
- **2026-08-31 (11)** — M7 round-robin load balancing landed.
  `ApiDefinition.target_list: Vec<String>` (non-empty = enabled,
  no separate bool): when set, upstream requests rotate across the list and
  `target_url` is **not** used for forwarding (it stays
  required as the canonical/dashboard URL). Each entry is validated like
  `target_url` and may carry its own base path. Runtime: `UpstreamTarget`
  now holds `targets: Vec<UpstreamAddr{scheme, authority, base_path}>` plus
  a clone-shared `Arc<AtomicUsize>` cursor; `next_addr()` is lock-free,
  pod-local (no cross-pod coordination), and single-target APIs
  skip the atomic entirely. `rewrite::upstream_path_and_query` takes the
  selected addr for its base-path join. Versioning: `VersionOverrides`
  gained `target_list` (wholesale replace; `[]` reverts the version to its
  `target_url`), and validation **rejects** a `target_url` override whose
  effective `target_list` is non-empty — it would silently do nothing.
  `/g2/node` now lists `target_list` per API. e2e test proves A,B,A,B
  alternation with per-entry base paths and an unroutable `target_url`.
  Not done (deliberate): weighted/least-conn strategies and per-target
  health — eviction is exactly the next checkbox (upstream health checks),
  which should hook into `next_addr()`. Next: M7 upstream health checks
  with eviction.
- **2026-08-31 (12)** — M7 upstream health checks with eviction landed.
  `ApiDefinition.health_check: Option<HealthCheckConfig>` (path — joined
  onto each address's base path — interval_ms/timeout_ms/
  unhealthy_threshold/healthy_threshold; all defaulted). Runtime is new
  `g2-proxy::health`: per-target checker task spawned at route-build time
  probing every address concurrently (`GET`, 2xx-within-timeout = healthy)
  through the shared Forwarder client; flags live in a `HealthState`
  (`Vec<AtomicBool>`, all-healthy at build) that `next_addr()` reads
  lock-free, advancing the cursor past evicted addresses so the healthy
  subset keeps round-robining. **Eviction never empties the pool**: all
  addresses down → plain rotation (fail open, like the limiter's
  storage-error stance). **Lifecycle is Weak-based**: the checker holds
  only a `Weak<UpstreamTarget>` and exits on its first tick after a reload
  drops the old table — no abort plumbing; spawn is skipped (warn) without
  a tokio runtime, so sync `RouteTable::build` in tests still works. The
  base target of a versioned API gets no state/checker (it never
  forwards); `VersionOverrides` gained `health_check` (wholesale replace),
  and each version's own target is probed. `/g2/node` APIs now carry
  `target_health` (null = unchecked or versioned). New g2-proxy dep:
  futures-util (join_all). Verified: unit (thresholds/reinstatement/
  task-exit-on-drop), e2e (dead target evicted → all requests 200), and
  **live** (real gateway: `/g2/node` flipped [true,true]→[false,true],
  6×200 while evicted, then →[true,true] after the upstream returned;
  evicted/reinstated log lines). k8s smoke deliberately not extended
  (needs a second in-cluster upstream; revisit if M7 gets a deploy pass).
  Next: M7 circuit breaker per route; retries for idempotent methods —
  the breaker can read the same per-address health idea but should trip
  on live traffic, not probes.
- **2026-08-31 (13)** — M7 circuit breaker + idempotent retries landed.
  `ApiDefinition.circuit_breaker: Option<CircuitBreakerConfig
  {failure_threshold=5, cooldown_ms=30000}>` — **a deliberate design
  choice**: consecutive failures per route (like the health thresholds),
  not percent-over-samples per endpoint, because a sample window
  can't be lock-free. Runtime is `g2-proxy::breaker`: classic three-state
  breaker whose (state, transition-timestamp) live packed in one
  `AtomicU64` (every transition is a single CAS; failure streak in a
  separate relaxed counter), consulted only in the forwarder. Failures =
  transport errors, timeouts, upstream 5xx (final outcome after retries —
  retries mask per-address failures, health checks own those); open →
  fast 503 "upstream circuit open" with **no** `UpstreamLatency` stamped;
  half-open admits one trial via CAS, and an abandoned trial slot
  (client gone mid-flight) is reclaimed after another cooldown; straggler
  successes can't close an open circuit. `upstream_retries: u32` (≤10,
  default 0): extra attempts on **transport failure only** (not timeouts
  — the one per-API timeout budget spans all attempts — and not 5xx),
  each attempt re-picks `next_addr()` (synergy with LB + eviction), and
  only idempotent methods (post-transform) with `is_end_stream()` bodies
  qualify — a streamed body can't be replayed, so bodied PUTs get one
  attempt. The forwarder's single-attempt path moves headers instead of
  cloning (hot-path rule). Both fields get `VersionOverrides` (wholesale;
  `upstream_retries: 0` disables per version), per-version targets carry
  their own breaker like health state (base target: none). `/g2/node`
  APIs now carry `circuit_breaker` ("closed"/"open"/"half_open", null
  when off/versioned); OpenAPI schema registered. Verified: unit (state
  machine incl. trial-slot reclaim), forward-level over real TCP (trip on
  5xx, recover, failed trial re-opens, POST/bodied-PUT not retried), e2e
  through a full gateway, and **live** (breaker open→trial→closed in
  `/g2/node` + logs; 6/6 200s against a half-dead LB pool). Next: M7's
  last box — response caching (Redis, per-API TTL, safe methods only).
- **2026-08-31 (14)** — **M7 complete.** Response caching landed.
  `ApiDefinition.cache: Option<CacheConfig {ttl_secs=60,
  max_body_bytes=1MiB}>` (+ `VersionOverrides.cache`, wholesale). Runtime is
  `CacheLayer` (g2-middleware), between mock and the api-id header — hits
  stay authed/rate-limited, stored copies are raw upstream responses
  (response transforms re-apply live), mocks never cached. Entries are JSON
  (status + base64 headers/body) under `g2:{org}:cache:{scope}:{sha256("
  METHOD path?query")}` where scope = api_id or `api_id:version`, written
  with plain `Storage::set` + TTL — **no new Storage ops**, so both
  backends just work. Cached: safe methods (GET/HEAD/OPTIONS), 2xx only,
  and **never `Set-Cookie` responses** (a deliberate safety rule: the
  cache is shared across clients). Fail open on storage errors;
  corrupt entry = miss + overwrite. A miss adds no latency: the body
  streams to the client through a recording tee, and a clean completion
  within the cap spawns a background write. **Gotcha:** hyper never polls a
  fixed-length body to the final `None` frame (it stops at the declared
  length), so the tee must also treat frame + `is_end_stream()` as
  completion — the e2e caught this. Verified live: two gateway processes
  sharing real Redis — miss on pod A, `x-g2-cache: hit` replay on both
  pods, per-query keys, POST bypass, TTL 59s in Redis. Not done
  (deliberate): cache-flush admin endpoint (key schema is prefix-scannable
  for it), Vary/no-store semantics, per-path cache lists. Next milestone:
  M8+ extended parity — re-prioritize with the user first; the deferred
  M2 `jwks_url` box is also still open (TLS landed; needs a fetch-client
  choice).
- **2026-08-31 (15)** — **M2 fully complete.** The deferred `jwks_url` box
  landed. Fetch-client decision (the one the TLS entry left open): the
  proxy's shared hyper-rustls client, consumed through a new
  `JwksFetch`/`SharedJwksFetch` trait in g2-middleware (same inversion as
  `SharedStorage` — g2-middleware stays HTTP/TLS-free) and implemented by
  `HttpJwksFetch` in g2-proxy over `Forwarder::client()` (10s timeout, 1 MiB
  body cap via `Limited`). Config: `jwks_url` + optional `jwks_refresh_secs`
  (default 300) on the `Jwt` variant; rs256-only, exactly one of
  `public_key_pem`/`jwks_url`. Runtime: `g2_middleware::jwks::JwksCache` —
  pod-local `ArcSwap<HashMap<kid, DecodingKey>>` (lock-free reads per
  ADR-0001), background refresher copying the health-checker lifecycle
  (Weak, self-exits on table swap; eager first fetch), on-miss refetch for
  unknown kids behind a CAS-gated 10s cooldown, stale-on-error (a
  *successful* empty set is authoritative — that's revocation). Tokens
  must carry a `kid` (no try-all-keys; confusion-attack surface) and the
  per-layer RS256 `Validation` keeps HS256 alg-confusion dead.
  `AuthLayer::from_config` grew an `Option<SharedJwksFetch>` parameter;
  `RouteTable::build`'s signature is unchanged. Tests: fake-fetcher unit
  tests (rotation, cooldown, stale-on-error, no-kid, alg confusion), real
  TCP fetcher tests (500/oversized/dead port), a router test proving the
  1s periodic loop fetches and stops after table drop, and a
  `jwt_jwks_end_to_end` e2e (401/200/403 + rotation via periodic refresh).
  Not done (deliberate): non-RSA JWKS keys (gateway only speaks
  hs256/rs256), per-API custom CA for the JWKS endpoint (use
  `Forwarder::with_tls_config`). Next: M8+ extended parity —
  re-prioritize with the user first.
- **2026-08-31 (16)** — M8 TLS termination + mTLS landed (ADR-0003,
  `docs/tls.md` for operation). Config: `tls` block on `GatewayConfig`
  (`cert_file`/`key_file`/`client_ca_file`/`client_cert_mode:
  none|optional|required`) + `--tls-*`/`G2_TLS_*` mirrors; bad PEM fails
  startup, never falls back to plaintext. Server: `g2way::tls`
  builds the `tokio_rustls` acceptor (explicit `ring` provider via
  `builder_with_provider` — no global install; ALPN h2+http/1.1);
  `serve`/`serve_tls` share one accept loop, with the handshake moved
  onto the connection's task under a 10s timeout. **Surprise:** hyper-util
  0.1.20's `GracefulShutdown::watcher()` is what makes that work —
  clone a `Watcher` per accept, `watcher.watch(conn)` post-handshake;
  mid-handshake connections are deliberately not drained. mTLS auth:
  new `ConnectionInfo { tls, client_cert_fingerprint }` extension
  (g2-middleware stays TLS-free; `Gateway::handle` grew the param),
  `AuthConfig::Mtls {}` resolves `mtls:{sha256(cert DER)}` through
  `authenticate_stored_token` — so provisioning is the ordinary key CRUD
  (`PUT /g2/keys/mtls:{fp}`, zero admin changes) and certs get full
  session semantics (rate/quota/ACL/policy). CA-signed-but-unprovisioned
  = 403 (transport vs authorization split). Also fixed: the hardcoded
  `x-forwarded-proto: http` in rewrite.rs is now connection-truthful.
  **Surprise:** rustls-pki-types 1.15 PEM file helpers need no new dep or
  feature (`rustls::pki_types::pem::PemObject`). Tests: tls.rs +
  config/auth unit tests, 7-case `tls_e2e.rs` with an rcgen-minted PKI
  (CA, `localhost` server cert, good + rogue-CA clients) — no external
  services. Verified live against local httpbin with openssl-generated
  certs: termination 200 + `X-Forwarded-Proto: https`, `required`
  no-cert handshake alert, unprovisioned 403, admin-provisioned 200,
  ALPN h2, graceful drain. Deliberate limits (ADR-0003/doc): no cert
  hot-reload (restart to rotate), admin listener plaintext, no SNI
  multi-cert, no CRL/OCSP (revoke = delete the key), k8s manifests stay
  plaintext (doc has the Secrets walkthrough). Next: rest of M8+ —
  re-prioritize with the user.
- **2026-08-31 (17)** — M9 GraphQL opened (full box list) and its
  first slice landed: proxy mode + the whole protection suite (ADR-0004,
  `docs/graphql.md`, `examples/apis/graphql.json`). Config: `graphql` block on
  `ApiDefinition` (`schema` SDL required, `introspection_enabled`,
  `max_query_depth`, `playground.path`, `persisted_queries[]`), per-version
  overridable; per-key grants landed in the previously-empty `ApiAccess`
  (`allowed_types`/`restricted_types` with `"*"` + allow-wins,
  `disable_introspection`, `max_query_depth` where `-1` lifts) — **`ApiAccess`
  lost `Copy`**, policies inherit for free. Crate: `apollo-compiler` 1.x
  (pure Rust; schema compiled at route-build, per-request
  `ExecutableDocument::parse_and_validate`, typed selection sets carry the
  parent type for `field: X is restricted on type: Y`). New `GraphQlLayer`
  (chain slot 12, between rate-limit and header transforms; the ordering doc
  in `chain.rs` is renumbered) also serves the GraphiQL playground
  (pinned jsdelivr assets, behind auth) and rewrites persisted
  GraphQL-as-REST endpoints (`{param}` path regexes + pre-parsed operations
  precompiled; `$path.`/`$header.` variable substitution). **First layer to
  buffer a request body**: bounded `Limited` collect (cap =
  `max_request_body_bytes` else 1 MiB), exact bytes re-emitted; the
  size-limit layer's `RequestTooLarge` now surfaces in this collect and is
  mapped to 413 here; forwarder retry gate deliberately unchanged (ADR-0004).
  Error shapes are mixed by design (403 `{"error":…}` for depth and
  introspection, 400 `{"errors":[…]}` for validation/field perms);
  pure-introspection documents bypass depth checks. **Surprise:** `cargo test -p g2-middleware`
  alone never compiled (pre-existing: `tokio/test-util` for cache.rs's
  paused-clock test only arrives via workspace feature unification) — use
  `cargo test --workspace`, which is what `make check` runs. Tests: ~30 new
  (g2-core config/session/versioning, layer unit tests incl. size-limit
  interplay + chain-position, 7-case `graphql_e2e.rs` with a fake GraphQL
  upstream; openapi registration test extended). Deliberately not done
  (unchecked M9 boxes): introspection schema sync, subscriptions (needs the
  M8+ WebSocket box first), UDG/federation, GraphQL-aware caching, APQ,
  batching (a JSON-array envelope is rejected). Next: the remaining M8+/M9
  boxes — re-prioritize with the user.
- **2026-09-01** — M8+ OAuth2/OIDC landed (`docs/oidc.md`); the combined
  "OAuth2/OIDC, HMAC signatures, per-endpoint rate limits" box was **split
  into three** (user-confirmed scope: OIDC first). Shape is external-IdP
  validation only — deliberately no gateway-hosted authorization server
  (would be its own box if ever wanted). `AuthConfig::Oidc {issuer_url,
  audiences (required non-empty), jwks_url?, jwks_refresh_secs?, header,
  identity_claim, policy_claim="azp", policy_map}`. Discovery lives in
  `JwksCache` (new `via_discovery`): the well-known doc is fetched through
  the existing `JwksFetch` trait on the first refresh, its `issuer` must
  match byte-exactly, and `jwks_uri` is pinned in a `OnceLock` until a
  reload. Verification reuses the jwt machinery (`verify_jwt_claims`
  extracted) with precomputed `iss`/`aud`/`exp`-required `Validation`;
  identity namespace is `oidc:{identity}`. Policy mapping resolves through
  `fetch_active_policy` (extracted from `resolve_policy`, same
  403/500/503 contract); ephemeral-session-with-policy is a first (jwt
  sessions still never carry policies). **Gotcha:** jsonwebtoken 10's
  default `validate_aud=true` + no expected audience rejects any
  aud-bearing token — that's why `audiences` is required (also a
  deliberate hardening choice, as is single-claim client-id mapping
  instead of aud/azp heuristics). **Boot race worth knowing:** on a
  fresh route, requests can 403 until the eager background key fetch
  lands (on-miss refetch is cooldown-gated behind it) — the e2e polls for
  it; same pre-existing behavior as jwt+jwks. RS256-only (JWKS filter
  unchanged); ES256 is a cheap follow-up. No ADR (JWKS precedent), no
  OpenAPI changes (inline variant). Next: M8+ HMAC request signatures or
  per-endpoint rate limits.
- **2026-09-01 (2)** — M8+ HMAC request signatures landed (`docs/hmac.md`,
  draft-cavage HTTP Signatures). `AuthConfig::Hmac
  {allowed_algorithms (default all of hmac-sha256/384/512; **no sha1** —
  hardening deviation), allowed_clock_skew_secs (default 300; explicit
  `null` disables — the field is deliberately **not** skip-serialized so
  `null` survives round-trips; while set, `date` must be among the *signed*
  headers or 403)}`. Session model: `KeySession.hmac:
  Option<HmacData{secret}>` mirroring `BasicAuthData` — but the secret is
  a **plaintext live credential** (HMAC needs it verbatim; session.rs
  module doc updated; admin GET returns it — redaction is a flagged
  follow-up). keyId → `hash_key("hmac:{keyId}")`, provisioning = ordinary
  `PUT /g2/keys/hmac:{keyId}`, zero admin changes (mtls pattern). Parsing/
  signing-string/verify live in new `g2-middleware::hmac` (pure & sync;
  params case-sensitive, unknown ignored, duplicates malformed;
  `(request-target)` byte-exact **full client path** incl. listen path —
  auth precedes the forwarder's strip; multi-values joined `", "`;
  percent-encoded signatures accepted for client compat).
  `authenticate_hmac` follows basic's shape: 401 only for unparseable
  credentials, single no-oracle 403 for the rest, dummy-HMAC for unknown
  keyIds (µs, inline — no spawn_blocking), `verify_slice` is already
  constant-time so **no direct `subtle` dep**. New workspace deps `hmac`,
  `httpdate` (both were already transitive). OpenAPI: `HmacAlgorithm` +
  `HmacData` registered (named types referenced by inline variants DO need
  it — the oidc "no changes" note is not a precedent for those). Gotcha:
  crate-root `mod hmac` shadows the `hmac` crate in use paths (the
  session-5 `mod redis` lesson) → `::hmac::…` throughout. Tests: 24 unit
  (g2-core config/session, hmac module KATs from RFC 4231, per-mode auth
  suite) + `hmac_auth_end_to_end` e2e. Not done (deliberate): rsa-sha256
  signatures, `(created)`/`(expires)`, body-digest verification. Next:
  M8+ per-endpoint rate limits.
- **2026-09-01 (3)** — M8+ per-endpoint rate limits landed
  (`docs/endpoint-rate-limits.md`), **API-level/aggregate flavor only**
  (user-confirmed scope; a key-level `access_rights[].endpoints`
  flavor is a possible future box). `ApiDefinition.endpoint_rate_limits:
  Vec<EndpointRateLimit {pattern, methods, rate: RateLimit}>`
  (g2-core::endpoints, PathRule conventions: unanchored regex on the full
  client path, empty methods = all, zero rate rejected) + a
  `VersionOverrides` arm (wholesale; per-version counters). Runtime extends
  `RateLimitLayer` (no new layer): compiled `EndpointLimits` checked
  **before** the `SessionContext` early-return, so keyless APIs and
  `ignore_auth_paths` matches — previously entirely unlimited — are now
  covered; router gating became `auth.is_some() || endpoint_limits.is_some()`
  and the `cache_scope` param was renamed `scope` (now also namespaces
  endpoint counters: `g2:{org}:endpointrl:{scope}:{index}`, index-keyed —
  reordering rules resets windows, documented). First match wins (mock
  precedent); denial = the same 429 + `X-RateLimit-*`/`Retry-After`; fail
  open on storage errors; endpoint-denied requests consume no session
  allowance (tested); spike guard deliberately covers only session checks.
  No Storage changes (`check_rate` on a new key), no ADR. Tests: 9 new
  layer units (incl. aggregate-across-identities and denial-spares-session
  proofs), router build test, 2 e2e (keyless 429 + ignored-path 429);
  `BrokenLimits` test double hoisted to module scope for reuse. Next: M8+
  WebSocket/SSE passthrough + gRPC passthrough (also unblocks M9 GraphQL
  subscriptions).
- **2026-09-01 (4)** — M8+ WebSocket/SSE passthrough landed
  (`docs/websockets.md`); the "WebSocket/SSE; gRPC" box was **split** — gRPC
  passthrough is its own box (needs end-to-end h2: h2c/ALPN upstream client
  + trailer forwarding; the forwarder still pins upstream requests to
  HTTP/1.1). Config: `ApiDefinition.enable_upgrades` (default **off** —
  hop-by-hop stripping keeps downgrading upgrades to plain HTTP unless the
  API opts in) + a `VersionOverrides` arm. Server: the accept loop now uses
  hyper-util `serve_connection_with_upgrades` (`UpgradeableConnection`
  implements `GracefulConnection`, so the drain plumbing is unchanged —
  but established tunnels are deliberately **not** part of the drain).
  Forwarder: when the API opted in, the client sent `Upgrade`, and hyper
  stamped an `OnUpgrade` request extension (absent on h2 requests — the
  natural h1-only gate), the upgrade headers are re-added after hop-by-hop
  stripping; an upstream 101 spawns a `copy_bidirectional` tunnel task
  joining both `OnUpgrade`s (the legacy client drives h1 connections
  `with_upgrades()` internally — same path reqwest relies on). A 101 with
  no client upgrade in flight → 502. The handshake runs the full chain
  (auth/limits/analytics see a normal GET) and `upstream_timeout_ms`
  covers only the handshake. SSE needed **zero code**: bodies already
  stream and the timeout only bounds response headers — proven by a new
  e2e where the client receives event 1 while the upstream deliberately
  withholds event 2, and the stream survives past the timeout. Doc warns:
  don't enable `cache` on SSE APIs (the tee buffers up to `max_body_bytes`
  for a body that never completes). New workspace tokio feature `io-util`.
  Tests: 2 forwarder units (flag plumbing, unsolicited-101→502) + 3 e2e
  (`streaming_e2e.rs`: raw-handshake echo tunnel incl. teardown,
  default-off downgrade, SSE streaming proof). M9 GraphQL subscriptions
  are now unblocked. Next: M8+ gRPC passthrough, or the plugin-system ADR.
- **2026-09-01 (5)** — M8+ gRPC passthrough landed (`docs/grpc.md`).
  Config: `ApiDefinition.upstream_http2` (default off, user-confirmed
  shape over an `h2c://` scheme) + a `VersionOverrides` arm —
  when set, ALL the API's upstream traffic is HTTP/2: `http://` targets
  via h2c prior knowledge, `https://` via ALPN offering only `h2` (no h1
  fallback). Runtime: `Forwarder` now holds **two** pooled clients
  (hyper's legacy client pins protocol per pool — `http2_only(true)` is
  what makes plaintext connections h2c); `with_tls_config` **clones** the
  rustls config because hyper-rustls's `enable_http2()` mutates its ALPN
  list (a shared config would poison the h1 connector); selection is
  `Forwarder::client_for(&UpstreamTarget)` off a new build-time
  `UpstreamTarget.http2` flag (hot-path rule). `forward()` stamps
  `Version::HTTP_2` on the h2 path and re-adds `te: trailers` after
  hop-by-hop stripping (upgrade-header re-add pattern; only the
  `trailers` token — RFC 9113 §8.2.2 — so `te: gzip` stays stripped).
  Health probes switched to `client_for` (an h2-only upstream rejects
  h1 probes → would evict every address of exactly these APIs); JWKS
  fetch stays h1. Trailers needed **zero body work** — `ProxyBody` and
  every wrapper already forward trailer frames; the client-facing side
  already spoke h2 (auto-builder preface sniffing + TLS ALPN since M8).
  Validation rejects `upstream_http2`+`enable_upgrades` (no 101 over
  h2); cache/retries need no gating (gRPC is POST: never cached, never
  retried); breaker is blind to `grpc-status` trailers (documented).
  Cargo: hyper-rustls grew its `http2` feature — the only dep change.
  Tests: 4 g2-core units, 4 forward.rs units (h2c version/te/trailers,
  default-off pin, ALPN-h2-only TLS upstream, te-gzip), `grpc_e2e.rs`
  (grpc-shaped call with trailer assert through a real gateway,
  default-off h1 proof, versioned API mixing h1+h2 upstreams). Not done
  (deliberate): gRPC-Web/transcoding, message-level anything, examples/
  Makefile grpc upstream (e2e is the reference). M9 GraphQL
  subscriptions remain unblocked. Next: plugin-system ADR (WASM
  pre/post hooks) or service discovery / body transforms.
- **2026-09-01 (6)** — M8+ WASM plugin system landed (ADR-0005,
  `docs/plugins.md`), user-confirmed scope: custom ABI (not proxy-wasm/
  component model), v1 powers = header mutation + short-circuit responses,
  no body access. New crate **g2-plugin** (wasmtime 33 — pinned: 34+ raises
  MSRV past rust-version 1.85; `default-features=false`, no cmake/zstd in
  the tree, Docker build verified); g2-middleware gained `PluginLayer` +
  `PluginExec`/`PluginLoader` traits (jwks-style inversion — middleware and
  proxy crates never compile wasmtime; the binary builds `PluginHost`, like
  the rustls acceptor). ABI v1: freestanding module (zero imports — an
  empty `Linker` enforces no-WASI), exports `memory`/`g2_abi_version`/
  `g2_alloc`/`g2_hook(ptr,len)->i64` packed ptr/len; JSON in/out; no
  `g2_free` (fresh `Store` per invocation, dropped wholesale). Limits:
  epoch-deadline timeout (default 50ms, process-wide 5ms ticker thread on
  a Weak — JWKS-refresher lifecycle) + `StoreLimits` memory cap (16 MiB,
  `trap_on_grow_failure`). **Fail closed** (500) on trap/timeout/bad
  output — deliberate inversion of the limiter's fail-open, reasoned in
  ADR-0005 §4. Chain: pre = slot 10 (directly above auth), post = slot 13
  (below rate-limit); doc renumbered 1–18; both per-version
  (`VersionOverrides.plugins`), both under the api-id anti-spoof stamp.
  Config: `plugins{pre,post:[{name,path,config,timeout_ms,
  max_memory_bytes}]}` + gateway `plugins_dir`/`--plugins-dir`; paths
  shape-checked at validate, canonicalize+containment (symlink-proof) at
  load; broken module fails build loudly, reload keeps old table.
  **`RouteTable::build` params-struct refactor done** (the session-3 wish):
  `RouteResources` struct, all 9 call sites converted. Tests: WAT-authored
  guests via the `wat` dev-dep (no wasm32 toolchain in `make check`) — 18
  g2-plugin units (incl. infinite-loop-traps-at-50ms, needle-scan guest
  proving real input delivery), layer/chain tests with fakes, 7-case
  `plugin_e2e.rs` (incl. shipped-example test pinning
  `examples/plugins/header_tag.wat`'s hand-counted data length). Verified
  live: real gateway + `--plugins-dir` injected/stripped headers through
  the example plugin. Not done (deliberate): body access, response-header
  mutation on continue, base64 bodies, compile cache across reloads —
  ADR-0005 consequences list. Next: M8+ service discovery /
  body transforms, or an M9 GraphQL box (subscriptions unblocked).
- **2026-09-01 (7)** — M8+ service discovery landed (ADR-0006,
  `docs/service-discovery.md`); the "service discovery; body transforms" box
  was **split** (user-confirmed: discovery first, HTTP+JSON polling flavor;
  body transforms will use **minijinja** when they land).
  `ApiDefinition.service_discovery {endpoint, data_path, port_data_path,
  parent_data_path, scheme, interval_ms, timeout_ms}` — dotted-path
  extraction over the polled JSON (`extract_entries` in g2-core, pure +
  table-tested; covers Consul/etcd/Eureka shapes; deliberately no
  `use_nested_query`/`use_target_list` knobs) + a `VersionOverrides` arm. Core
  change (**scoped ADR-0001 amendment**): `UpstreamTarget.targets` became
  `Arc<ArcSwap<TargetSet {addrs, health}>>` — one designated swappable
  leaf; `next_addr` moved onto `TargetSet` (callers hold a load guard
  briefly), and `HealthState` now lives *inside* the set, making the
  flags-index-matches-addrs invariant structural (health checks + discovery
  coexist; the checker re-derives probe URIs/streaks on `Arc::ptr_eq`
  change; swapped-in sets start all-healthy). New `g2-proxy::discovery`
  refresher (JWKS/health lifecycle: Weak + `Handle::try_current` guard;
  first poll immediate, h1 client always): stale-on-error keeps the
  previous set on *any* failure incl. **empty results** (deliberate
  asymmetry vs JWKS revocation, reasoned in ADR-0006 §4); swap only on
  change (no health reset/log churn); seeds = `target_list`/`target_url`
  until the first success. `/g2/node` gained `live_targets` +
  `service_discovery {endpoint, last_success_unix_secs, last_error}`.
  Zero new deps (arc-swap/serde_json already in g2-proxy). Tests: g2-core
  config/extraction tables, forward swap/rotation units, discovery
  module suite (fake endpoint incl. failure table + task-exit),
  checker-follows-swap, 2-case `discovery_e2e.rs` (traffic follows catalog
  flips live; dead catalog = frozen targets keep serving). **Surprise
  (env):** the workspace `target/` had grown to 106G and filled the disk
  mid-`make check` — deleted `target/debug/incremental` (62G); worth an
  occasional `cargo clean`. Not done (deliberate, ADR-0006): DNS
  SRV/k8s-Endpoints sources, poll jitter, catalog-metadata weighting.
  Next: M8+ body transforms (minijinja), or an M9 GraphQL box
  (subscriptions unblocked).
- **2026-09-01 (8)** — **M8+ complete.** Body transforms landed (ADR-0007,
  `docs/body-transforms.md`): `ApiDefinition.transform_body {request,
  response: [{pattern, methods, template, content_type}],
  max_response_body_bytes}` — endpoint-scoped like `mock_responses`
  (full-client-path regex, first match wins; response rules match the
  *request's* method/path), inline minijinja templates (no file/base64
  modes), `VersionOverrides` arm. Context is named-key, not
  body-at-root: `body` (JSON or none), `raw`, `_g2 {method, path,
  query, headers, session.alias, status}`. Runtime `BodyTransformLayer`
  at **slot 16** (below header transforms: rejections untransformed,
  mocks/cache-hits transformed; doc renumbered 1–19): per-API
  `Environment<'static>` built at route-build (`add_template_owned`
  compiles at insert), fuel-bounded rendering (1M units — **no timeout
  machinery**, render is pure computation), **fail closed** (413 request
  over-cap / 500 render fail / 502 response over-cap-or-fail; ADR-0005 §4
  redaction rationale). First feature buffering *response* bodies (scoped
  ADR-0001 amendment: matching endpoints only); 1xx skipped so upgrade
  tunnels survive; trailers re-emitted via a two-frame `BufferedBody`
  (grpc-status intact); retry gate untouched. `size_limit` grew
  `is_over_limit` (graphql's LengthLimitError walk hoisted). New dep
  minijinja 2 (`builtins,serde,json,fuel`; no `multi_template` — include/
  extends are config-time errors). **Gotchas:** bare `{{ true }}` renders
  `True` (Python-style) — docs steer JSON output to `| tojson`;
  `{{ 1 / 0 }}` is `inf`, not an error. Tests: 6 g2-core units + 16
  layer units + 2 chain-ordering + 4-case `transform_body_e2e.rs`.
  **Env note:** target/ hit ENOSPC mid-build (accumulated 139G!) →
  `cargo clean` + cold rebuild this session; the plan is to `cargo clean`
  at session end going forward. Next: an M9 GraphQL box — subscriptions
  over WebSocket (unblocked) or schema sync from introspection.
- **2026-09-02** — M9 schema sync from upstream introspection landed
  (ADR-0008, `docs/graphql.md` §Schema sync), user-confirmed shape:
  **pod-local ArcSwap** (no storage write-back — file-def collision +
  multi-pod write races reasoned in the ADR). `GraphQlConfig.schema_sync
  {interval_ms=600000, timeout_ms=10000, url?, headers}`; `GraphQlShared`
  now holds `ArcSwap<GraphQlSchemaState {sdl, schema, persisted_docs}>` —
  the **second designated swappable leaf** after ADR-0006's TargetSet; the
  persisted docs ride the state because a swap re-validates them (any
  failure fails the whole sync — stale-on-error everywhere, unchanged SDL
  = pointer-equal no-op). apollo-compiler has no introspection-JSON import
  → hand-written `introspection_to_sdl` (g2-middleware::graphql_sync, pure
  serde_json→SDL; skips builtin types/scalars/directives, verbatim
  defaultValues, block-string descriptions; compiled via the same
  `Schema::parse_and_validate` as config). **Test trick worth reusing:**
  fixtures are generated by apollo's own `introspection::partial_execute`
  answering our INTROSPECTION_QUERY from an SDL — round-trips a real
  server's response shape, no hand-written JSON. Refresher =
  g2-proxy::graphql_sync (discovery lifecycle: Weak×2 + `SyncNudge`
  detached waiter so the sleep holds no state); fetch via
  `client_for`+`next_addr` (follows LB/discovery/eviction) or
  `schema_sync.url` over the h1 pool; 4 MiB cap. Admin trigger: `POST
  /g2/graphql/sync` → `g2:{org}:channel:graphql-sync` → per-pod
  `reload::listen_graphql_sync` walks the route snapshot and `trigger()`s
  (Notify permit coalesces; no cooldown needed). `/g2/node` gained
  `graphql_schema_sync {last_success_unix_secs, last_error}` (null for
  versioned APIs — per-version sync, discovery precedent). Gateway-side
  `introspection_enabled=false` does NOT block sync (polices clients, not
  the fetch — documented). ~35 new tests incl. `graphql_sync_e2e.rs`
  (seed rejects field → upstream grows schema → 400→200 live) + **verified
  live**: real binary, admin trigger flipped `{extra}` 400→200 with the
  full log chain. Next M9 box: GraphQL subscriptions over WebSocket
  (still unblocked) or UDG (needs an execution-engine ADR first).
- **2026-09-02 (2)** — M9 GraphQL subscriptions over WebSocket landed
  (ADR-0009, `docs/graphql.md` §Subscriptions), user-confirmed shape:
  **terminate & police** (not opaque passthrough), both subprotocols
  (`graphql-transport-ws` + legacy `graphql-ws`), tokio-tungstenite 0.30
  (`default-features=false`, MSRV 1.85 = ours; frame codec only — both
  HTTP handshakes stay on hyper's passthrough, so Key/Accept cross end to
  end and the gateway needs no sha1; streams wrapped via
  `from_raw_socket`). Config: `graphql.subscriptions {enabled,
  max_message_bytes?}` (presence-enables like playground; cap defaults to
  `max_request_body_bytes` else 1 MiB; validation requires a Subscription
  root and rejects `upstream_http2`); **implies** forwarder upgrade
  capability without `enable_upgrades` (every WS handshake on a GraphQL
  API is policed or rejected — no opaque bypass possible). Seam:
  `GraphQlWsTunnel` request extension (g2-middleware, no trait inversion
  — g2-proxy already deps g2-middleware) stamped by the GraphQL layer's
  new WS-handshake branch (before the persisted loop; 400 when disabled /
  no known subprotocol offered), removed at the forwarder's upgrade gate,
  run in `upgrade_response`'s detached task instead of
  `copy_bidirectional`; the upstream's 101 subprotocol is authoritative
  (unknown pick → 502 fail-closed; none echoed → **union** policing,
  error shape per the message's own protocol). `enforce` refactored into
  shared `check_document` → `Violation` (HTTP mapper + WS error mapper).
  Policing: subscribe/start payloads (any operation type) parsed against
  the ArcSwap schema state per message (sync applies to live tunnels);
  violations → per-protocol `error` with the id, connection stays open;
  invalid JSON/unknown type/binary → close 4400 (legacy:
  connection_error + 1002); WS pings leg-local (auto-pong + flush);
  upstream→client verbatim, zero parsing. **Flagged behavior change**:
  subscription operations over plain HTTP now 400 (resolved via
  `operationName`; multi-op docs selecting a query still pass).
  `futures-util` moved dev→real dep in g2-middleware (`std`+`sink`).
  Tests: 4 g2-core config + truth table, 17 graphql_ws units (policer
  table + duplex relay sessions incl. denied-never-crosses), 5 graphql.rs
  handshake/HTTP-hardening units, 2 forward.rs units, 6-case
  `graphql_subscriptions_e2e.rs` (real tungstenite client/upstream:
  stream-end-to-end incl. Accept passthrough, authed grants deny,
  depth, legacy session + wrong-vocab close, no-subscriptions 400,
  unpoliceable-upstream 502; upstream message log proves denials never
  cross). **Gotcha:** `cargo test -p g2-middleware` alone fails on
  tokio `test-util` feature unification (comes via g2-storage's
  dev-deps) — test with `-p g2-middleware -p g2-storage` or the whole
  workspace. Not done (deliberate, ADR-0009 consequences): per-message
  analytics/metrics, mid-tunnel grant re-checks, RFC 8441. Next M9 box:
  UDG (needs an execution-engine ADR first) or federation.
- **2026-09-02 (3)** — M9 Universal Data Graph landed (ADR-0010,
  `docs/graphql.md` §UDG), user-confirmed shape: REST + GraphQL data
  sources on **root fields only** (nested data projected from the parent
  JSON), minijinja templating. `execution_mode: "udg"` +
  `data_sources {"<RootType>.<field>": {kind: rest|graphql, …}}`;
  validation requires full root-field coverage and rejects
  schema_sync/enabled-subscriptions in udg (so the ADR-0008 schema leaf
  never swaps → `UdgEngine` lives schema-independent in `GraphQlShared`,
  no third swappable leaf). **Big find:** apollo-compiler 1.32 ships a
  public spec-compliant executor (`resolvers::Execution` — CollectFields,
  @skip/@include, argument+result coercion, null propagation, error
  paths, local introspection) — no hand-rolled projector, no new deps.
  **Its async mode is unusable on our chain** (execution future holds
  non-`Send` resolver state) → three-phase design: sync *record* pass
  (resolver notes root fields + coerced args + merged selections, returns
  `SkipForPartialExecution`) → `Send` *fetch* phase (join_all for
  queries — concurrent, better than apollo's own serial engine — serial
  for mutations) → sync *stitch* pass over the prefetched JSON
  (`PrefetchedRoot`/`JsonNode`; REST trees key by field name, GraphQL
  trees by response key; abstract types need upstream `__typename`).
  GraphQL sources get the field's printed sub-selection + transitively
  used fragments + used variable defs/values only (all-variables-used
  validation makes over-sending an upstream error). Fetch seam =
  `UdgFetch` trait inversion (JwksFetch pattern; `HttpUdgFetch` on the
  h1 pool, threaded through `inner_layers`). `extract_query` now carries
  `variables` (POST envelope + GET param; proxy mode still forwards
  original bytes untouched). Source failures → per-field GraphQL errors
  naming only the source key (detail logged, ADR-0005 §4). 17 udg units
  + 9 g2-core config tests + 6-case `graphql_udg_e2e.rs`, **verified
  live** (real binary stitched two REST fetches, variables through the
  URL template, local introspection). Not done (deliberate, ADR-0010):
  nested-field sources/batching, REST `data_path`, per-source
  LB/health/breaker, udg subscriptions. Next M9 box: federation, or
  GraphQL-aware response caching.
- **2026-09-02 (4)** — M9 federation landed (ADR-0011, `docs/graphql.md`
  §Federation): two new execution modes. **`subgraph`** = proxy mode with a
  federation-aware schema: `g2_core::federation` injects missing federation
  directive/type definitions and augments the SDL with `_service`/
  `_entities` + the `_Entity` union (idempotent — an already-expanded SDL
  round-trips), so a federating router's reserved queries validate and are
  policed like any operation; schema sync/subscriptions keep working.
  **`supergraph`** = the gateway as router: `graphql.supergraph.subgraphs
  [{name, url, sdl, headers, timeout_ms, max_response_bytes}]`, composed at
  write/load time (`federation::compose` — root fields single-owner, entity
  fields merged with per-field ownership + per-subgraph canonical keys,
  value types must be identical, fed directives stripped, composed SDL
  re-validated as the final gate; `graphql.schema` gained
  `#[serde(default)]` and must be **empty** here). Execution extends the
  ADR-0010 engine: record (reused) → **plan** (new
  `graphql_federation::Planner` splits selection trees by ownership,
  inlines fragments, injects `__typename` + collision-proof `g2__<key>`
  aliases) → fetch (owner per root field; per level one batched
  `_entities` POST per (entity, target) with a collision-proof
  `$g2_representations` var, grandchildren resolve on the owned entity
  values pre-merge, mask-aligned merge walk) → stitch (reused,
  ResponseKey). Failures: partial data, errors name only the subgraph.
  Rejected loudly in v1: @requires/@override, interface entities, nested
  keys, shared root fields, non-Query/Mutation roots, subgraph
  Subscription roots; @provides ignored. Engine rides `UdgFetch` (static
  headers, schema-sync precedent); no new deps anywhere. ~30 new tests
  (8 federation-core, 12 config, 10 executor + subgraph layer test) +
  4-case `graphql_federation_e2e.rs` (real gateway + two real subgraph
  upstreams: stitch with upstream-body assertions, local introspection,
  dead-subgraph partial data, subgraph-mode reserved-query passthrough).
  Next M9 box: GraphQL-aware response caching, or the stretch items
  (complexity limits, APQ).
