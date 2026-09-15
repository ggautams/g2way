# ADR-0010: GraphQL Universal Data Graph execution

Date: 2026-09-02 · Status: accepted

## Context

Every GraphQL feature so far (ADR-0004, -0008, -0009) polices traffic that a
single upstream GraphQL server ultimately executes. A Universal Data
Graph inverts that: the gateway itself is the executor. An API declares a
GraphQL schema and maps its fields to *data sources* — REST endpoints and
GraphQL services — and the gateway answers each query by calling the mapped
sources and stitching their JSON into one spec-shaped GraphQL response. No
request is forwarded; there is no "the" upstream. ADR-0004 §7 deliberately
deferred this because it needs an execution engine — the machinery that
collects fields, applies fragments and `@skip`/`@include`, coerces arguments
and results, propagates nulls, and attributes field errors to response
paths. This ADR is that execution-engine decision. The user-confirmed v1
shape: REST + GraphQL data sources, attached to root fields only, with
minijinja templating (ADR-0007's engine) for source requests.

## Decisions

1. **Execution engine: apollo-compiler's `resolvers::Execution`, run in
   three phases — not hand-rolled.** apollo-compiler 1.32 (already the
   schema and validation engine since ADR-0004) ships a public,
   spec-compliant executor that drives CollectFields, field merging,
   aliases, fragment spreads, `@skip`/`@include`, argument coercion
   (variables substituted, defaults applied), result coercion, null
   propagation, and field-error `path`/`locations` — every spec trap a
   bespoke projector would re-implement badly. Its *async* mode is
   unusable here (the execution future holds non-`Send` resolver state
   across awaits; every future in the middleware chain must be `Send`),
   so execution is split: (1) a synchronous **record** pass whose resolver
   notes each collected root field — response key, spec-coerced arguments,
   merged selections — and returns `SkipForPartialExecution`; (2) a
   **fetch** phase calling the recorded fields' data sources with plain
   `Send` futures — concurrently (`join_all`) for queries, serially in
   selection order for mutations, per the spec; (3) a synchronous
   **stitch** pass resolving root fields from the prefetched JSON and
   projecting nested selections out of it. The engine still owns every
   spec decision; the double pass costs one extra CollectFields walk over
   root fields only. Considered: **hand-rolled selection projection**
   (rejected — duplicates the engine we already ship for introspection,
   and field merging/null propagation are exactly where hand-rolled
   executors go subtly wrong), **async-graphql/juniper** (rejected —
   server frameworks with their own schema representation; a second
   GraphQL stack in the tree), **vendoring apollo-router's planner**
   (rejected — not consumable as a library at sane cost), **driving
   `execute_async` on a dedicated thread** (rejected — a thread hop per
   request to work around a `Send` bound the phase split removes for
   free, and the split buys concurrent fetches apollo's serial engine
   would not).

2. **UDG is an execution mode inside `GraphQlLayer` (chain slot 14), not a
   new layer.** `GraphQlConfig.execution_mode` gains its planned second
   variant, `udg`. The request pipeline is unchanged through parse,
   subscription rejection, and grant/depth/introspection enforcement; where
   proxy mode forwards, udg mode executes locally and returns — `inner` is
   never called, like the playground and persisted-query short-circuits
   that already exist in the layer. Considered: a new chain slot (rejected
   — every existing GraphQL protection must run first anyway, the mode
   branch is one `if`, and chain depth has a real cost: the
   `-Csymbol-mangling-version=v0` workaround exists because the linker
   choked on the current nesting).

3. **Data sources attach to root fields only, keyed `"<RootType>.<field>"`
   (e.g. `"Query.user"`), and validation requires full coverage.** Every
   non-meta field of the schema's query and mutation root types must be
   mapped; an unmapped field, an unknown key, or a key naming a non-root
   type is a config error at write/load time. Nested selections are
   projected from the parent source's JSON by the engine (missing keys
   resolve to null; nullability is enforced by result coercion). Considered:
   resolving unmapped fields to runtime nulls/errors (rejected — hides
   config typos; loud validation is the house rule), data sources on nested
   types (rejected for v1 — requires a planner with batching to avoid N+1
   fetch storms; future box).

4. **Two source kinds. `rest`: templated method/url/headers/body. `graphql`:
   the field's sub-selection forwarded as a standalone query.** A REST
   source renders its URL, header values, and optional body through
   minijinja and treats the response body as the field's JSON value. A
   GraphQL source prints the requested field (selection set, aliases, and
   arguments verbatim) plus the transitively referenced fragment
   definitions and the variable definitions its subtree uses, POSTs
   `{"query", "variables"}` to a fixed URL, merges the response's `data`
   value and appends its `errors` (message-only) to the stitched response.
   Considered: passing the client's whole document to GraphQL sources
   (rejected — other root fields belong to other sources), per-source
   response-path remapping for REST (a `data_path`; deferred, the
   service-discovery `data_path` precedent can be lifted later).

5. **The fetch seam is a `UdgFetch` trait inversion, implemented in
   g2-proxy over the Forwarder's HTTP/1.1 pool.** g2-middleware stays free
   of hyper/rustls (the `JwksFetch` precedent): the executor holds an
   `Arc<dyn UdgFetch>` taking method/url/headers/body/timeout/cap and
   returning status + capped bytes; g2-proxy's implementation rides the
   shared h1 pool with `tokio::time::timeout` + `http_body_util::Limited`
   (the schema-sync fetch mechanics). Data-source URLs are absolute, so
   fetches do not follow the API's target list, discovery, or health
   eviction — a udg API's sources *are* its upstreams, and per-source
   LB/discovery is a future box. Considered: a request extension driven by
   the forwarder (ADR-0009's seam; rejected — the response is built from
   many fetches mid-execution, not from one tunnel at the chain's tail),
   moving an HTTP client into g2-middleware (rejected — dependency
   direction).

6. **Templating is minijinja per ADR-0007, compiled at route-build time.**
   One `Environment<'static>` per API holds every source template
   (registry-keyed like body-transform rules), fuel-bounded (1M units),
   `AutoEscape::None`, syntax-checked at config validation. The render
   context is `{ args, _g2: { method, path, headers, session: { alias } } }`
   — `args` are the engine-coerced GraphQL field arguments (variables
   already substituted, defaults applied), `_g2` mirrors the body-transform
   context for the client request. Considered: Go-template-style
   `{{.arguments.x}}` placeholders (rejected — a second bespoke template
   dialect on top of minijinja).

7. **Error semantics are GraphQL-spec field errors; request-level failures
   are 400.** A source failure (transport error, timeout, non-2xx,
   unparseable JSON, template render failure, response over cap, abstract
   type without `__typename`) becomes a field error with the engine
   attributing `path`/`locations` and nulling per nullability — partial
   data with `errors` alongside, HTTP 200 (spec behavior). Upstream
   GraphQL-source errors are appended to `errors` message-only (no path
   translation in v1). Unknown/ambiguous `operationName` and variable
   coercion failures are request errors → 400. Error messages name the
   source key, never upstream URLs or bodies (the ADR-0005 §4 redaction
   stance).

8. **Introspection executes locally.** The engine's
   `enable_schema_introspection(true)` answers `__schema`/`__type` from the
   compiled schema with zero upstream traffic. The existing policing is
   unchanged and runs first: API-level `introspection_enabled: false` and
   per-key `disable_introspection` still 403 before execution.

9. **`target_url` stays required and is documented as unused for udg
   traffic.** Making it optional touches a non-`Option` serde field with
   many dependents (`UpstreamTarget`, the always-built `Forward` tail,
   admin/node reporting) for zero behavior: the udg branch never calls
   `inner`, so the dead tail is unreachable. Considered: optional-in-udg
   (rejected for v1 as pure churn; revisit if it confuses operators).

10. **`schema_sync` and enabled `subscriptions` are rejected in udg mode at
    validation.** Sync introspects "the" upstream — meaningless with no
    single upstream. Consequence, deliberately load-bearing: a udg API's
    `GraphQlSchemaState` leaf never swaps after build, so the compiled
    execution state (source lookup table, templates, environment) lives in
    schema-independent `GraphQlShared` with no re-validate-on-swap
    machinery — no third swappable leaf (ADR-0008's "bar stays high").
    Subscriptions in udg mode would make the gateway a streaming executor;
    future box, and `subscriptions.enabled: false` blocks remain parkable.

11. **Caps: per-source `timeout_ms` and `max_response_bytes`.** Timeout
    defaults to the API's `upstream_timeout_ms`; the response cap defaults
    to 4 MiB (the schema-sync precedent). Both are per *fetch*: a query's
    sources fetch concurrently (bounded by the slowest), a mutation's
    serially (bounded by the sum — spec-ordered side effects). The
    client-side request body cap is the existing GraphQL buffering bound,
    unchanged.

## Consequences

- The gateway becomes an executor: udg responses never touch `Forward`, so
  upstream latency, retries, the circuit breaker, and load balancing do not
  apply to data-source fetches (stats/analytics/metrics layers still count
  every request, as with mock responses). Per-source resilience is future
  work.
- REST sources must return the field's JSON shape directly (no `data_path`
  remapping yet); abstract-typed fields require upstream `__typename`.
- The record pass fetches a field even when result coercion would later
  error on it, and a skipped-by-directive field is never fetched — fetch
  effort follows CollectFields exactly.
- Persisted GraphQL-as-REST endpoints and the playground work unchanged in
  udg mode — persisted operations execute locally through the same engine.
- Data-source templates are minijinja (`{{ args.x }}`), and response
  reshaping is done by shaping the schema rather than by a `data_path`
  extraction step.
- g2-middleware gains no dependencies (apollo-compiler and minijinja were
  already there; `futures-util` provides `BoxFuture`/`stream`); g2-proxy
  gains only the `UdgFetch` impl.
- Not in v1 (future boxes if wanted): nested-field data sources with a
  batching planner, per-source LB/discovery/health/breaker, REST
  `data_path` remapping, upstream GraphQL error-path translation, udg
  subscriptions, GraphQL-aware caching, federation.
