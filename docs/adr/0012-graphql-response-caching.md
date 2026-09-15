# ADR-0012: GraphQL-aware response caching

Date: 2026-09-02 · Status: accepted

## Context

The M7 response cache (`ApiDefinition.cache`, chain slot 18) never helps
GraphQL traffic: it caches only safe methods (GraphQL rides `POST`), and in
gateway-executed modes (udg/supergraph, ADR-0010/-0011) the GraphQL layer
(slot 14) answers before slot 18 ever runs. Two identical GraphQL queries
therefore always cost two upstream round-trips (or two full record/fetch/
stitch executions). What identifies a GraphQL response is not the URL but
the operation: the query text, the operation name, the variables, and the
schema it was validated against. This ADR decides where a GraphQL-aware
cache lives, what it keys on, and what it refuses to store.

## Decisions

1. **The cache lives inside the GraphQL layer (slot 14), not the slot-18
   `CacheLayer`.** Only slot 14 has the parsed operation (and in
   udg/supergraph mode nothing below it runs). Configured as
   `graphql.cache` reusing the M7 `CacheConfig` shape (`ttl_secs` = 60,
   `max_body_bytes` = 1 MiB; presence-enables like `playground` and
   `subscriptions`); per-version support falls out of the wholesale
   `VersionOverrides.graphql` replace. The storage machinery (entry
   encoding, the recording-body tee, background writes, fail-open reads)
   is shared with `cache.rs`, not duplicated. Considered: teaching slot 18
   to parse GraphQL POSTs (rejected — it would re-buffer a body slot 14
   already parsed, and still never see udg/supergraph responses).

2. **Keys are `g2:{org}:cache:{scope}:graphql:{digest}`** with `scope`
   exactly the HTTP cache's (`api_id`, or `{api_id}:{version}`), keeping a
   future flush-by-API a plain prefix scan. The digest covers, in order:
   a SHA-256 of the active SDL, the operation name, the query text, and
   the canonical variables. The SDL hash is precomputed on the swappable
   schema state (ADR-0008), so a schema sync or reload naturally starts a
   fresh keyspace — no invalidation machinery; superseded entries age out
   via their TTL. Variables canonicalize by re-serializing through
   `serde_json::Value` (key-ordered maps), so `{"a":1,"b":2}` and
   `{"b":2,"a":1}` share an entry; unparseable `GET ?variables=` text is
   hashed verbatim (a spurious miss, never a leak). Query text is **not**
   normalized (whitespace/field order vary the key): the TTL
   is the whole contract, and normalization buys hit rate at the cost of
   canonicalization bugs becoming correctness bugs.

3. **Shared across clients, policed before every lookup.** Like the M7
   cache, the key deliberately excludes caller identity.
   The lookup runs strictly **after** every policing gate (parse,
   validation, depth, introspection control, per-key field permissions),
   so a client can never read a cached entry for a query it is not
   allowed to make. The remaining exposure — an upstream whose response
   for the *same allowed query* varies by caller — is the same one the
   HTTP cache documents: such APIs must not enable the cache. One case is
   machine-checkable and refused at validation time: a udg data-source
   template reading the per-request `_g2` context (headers, session
   alias) produces per-client responses by construction, so
   `graphql.cache` + a `_g2`-reading template is an invalid definition.
   Supergraph subgraph fetches carry only static configured headers
   (ADR-0011) and need no such guard. Considered: keying on the session
   hash (rejected as the default — it silently divides the hit rate by
   the number of clients and diverges from every other cache we ship).

4. **Only query operations are cached, and only clean successes.**
   Mutations and subscriptions bypass; a mutation does **not** invalidate
   (TTL-only, M7 parity — invalidation-on-write can't be correct without
   understanding the schema's data dependencies). A document whose
   selected operation is ambiguous forwards uncached (the established
   "ambiguity is the upstream's problem" stance). Stored entries must be
   `2xx`, carry no `Set-Cookie`, and — the GraphQL-aware part — parse as
   a JSON object without a non-empty top-level `errors` array, checked in
   the background write task so the client never waits on it. A transient
   upstream failure inside a `200` envelope is thus never replayed for
   the whole TTL. Persisted GraphQL-as-REST endpoints are cached too when
   their operation is a query; the substituted variables (which may carry
   per-client header/path values) are part of the key, so per-client
   persisted responses never cross clients.

## Consequences

- In proxy mode the cached copy is the response **after** header/body
  transforms (slots 15/16 sit below slot 14) — the opposite of the HTTP
  cache, which stores the raw upstream response and re-applies response
  transforms on every hit. A hit replays the transformed bytes without
  re-running the transforms; transforms that vary per request (e.g. a
  header transform injecting a per-request value into the response) will
  replay the *first* request's rendering. Documented in `docs/graphql.md`.
- Hits carry `x-g2-cache: hit` and no `UpstreamLatency` extension, so
  analytics records them without an upstream latency — exactly like
  slot-18 hits.
- A `GET ?query=` request on an API with **both** `cache` and
  `graphql.cache` can be stored by both layers (slot 18 keys it by URL).
  Harmless duplication; the layers answer at different depths.
- A versioned API with a version literally named `graphql` shares its
  HTTP-cache prefix (`{api_id}:graphql:`) with the *unversioned* form's
  GraphQL scope. Digest inputs differ (no false hits), but a future
  flush-by-prefix would co-flush them. Accepted; noted here.
- No invalidation endpoint (the M7 deferral stands); the prefix schema
  keeps one possible later.
- Gateway-executed (udg/supergraph) hits skip the fetch phase entirely —
  the largest win, since those responses cost N upstream calls each.
