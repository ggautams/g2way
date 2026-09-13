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
- [ ] Auth: JWT `jwks_url` fetch + cache (unblocked: rustls landed with the M7 TLS connector; still needs an HTTPS fetch client choice)
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
