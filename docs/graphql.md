# GraphQL

g2way can front a GraphQL upstream as a policing proxy (`proxy` mode):
every request is parsed as GraphQL, validated against a schema you
configure, and checked against depth limits, introspection rules, and
per-key field permissions **before** it reaches the upstream. In proxy
mode the gateway never executes GraphQL itself — valid, permitted requests
are forwarded byte-for-byte. In `udg` mode (Universal Data Graph, below)
the gateway *is* the executor, stitching REST and GraphQL upstreams into
one graph.

Design decisions live in [ADR-0004](adr/0004-graphql.md) (proxy mode and
protections) and [ADR-0010](adr/0010-graphql-udg.md) (UDG execution). A
runnable example definition is `examples/apis/graphql.json`.

## Enabling GraphQL on an API

Add a `graphql` block to the API definition:

```json
{
  "api_id": "countries",
  "name": "Countries GraphQL",
  "listen_path": "/countries/",
  "target_url": "https://countries.trevorblades.com/graphql",
  "auth": { "mode": "keyless" },
  "graphql": {
    "schema": "type Query { hello: String }",
    "max_query_depth": 8,
    "introspection_enabled": true,
    "playground": { "path": "/playground" }
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Kill switch; `false` disables all GraphQL handling. |
| `execution_mode` | `"proxy"` | `proxy` (forward to the upstream) or `udg` (the gateway executes; see below). Federation is later M9 work. |
| `schema` | — (required) | The GraphQL schema, SDL. Validated at write/load time; requests are validated against it. |
| `introspection_enabled` | `true` | `false` rejects `__schema`/`__type` queries with `403`. |
| `max_query_depth` | unlimited | Nested selection-set levels (`{ a { b } }` = 2); deeper queries get `403`. |
| `playground` | off | Serve a GraphiQL page (see below). |
| `persisted_queries` | `[]` | GraphQL-as-REST endpoints (see below). |
| `schema_sync` | off | Keep the schema in sync with the upstream via introspection (see below). |
| `subscriptions` | off | GraphQL subscriptions over WebSocket, policed message by message (see below). |
| `data_sources` | `{}` | UDG root-field → data-source map; required in (and exclusive to) `udg` mode (see below). |

The whole listen path becomes the GraphQL endpoint: clients `POST` a JSON
`{"query": …, "variables": …}` envelope to the listen root (or `GET` with
a URL-encoded `?query=` parameter). Requests that are not valid GraphQL
for the configured schema are answered `400` with a GraphQL-style
`{"errors":[{"message":…}]}` body and never reach the upstream.

GraphQL works with every auth mode, and the definition is per-version
overridable (`versioning.versions.<v>.graphql`, replaced wholesale) like
any other block.

## Per-key grants

GraphQL restrictions ride on the key session's per-API access entry
(and on policies, which carry the same map):

```json
{
  "access": {
    "countries": {
      "allowed_types":    [ { "name": "Query",   "fields": ["*"] },
                            { "name": "Country", "fields": ["name", "code"] } ],
      "restricted_types": [ { "name": "Country", "fields": ["phone"] } ],
      "disable_introspection": true,
      "max_query_depth": 4
    }
  }
}
```

- **`allowed_types`** — when non-empty, the key may select *only* the
  listed (type, field) pairs; everything else is `400`. A non-empty allow
  list wins: `restricted_types` is then ignored.
- **`restricted_types`** — block list, consulted while the allow list is
  empty. `"*"` matches every field of its type (non-recursive). A common
  pattern: block `{"name": "Mutation", "fields": ["*"]}` to mint
  read-only keys.
- **`disable_introspection`** — per-key introspection off, even when the
  API allows it.
- **`max_query_depth`** — replaces the API's limit for this key (larger
  or smaller); `-1` lifts it entirely; absent inherits the API's.

Field violations answer `400` with this message shape:
`{"errors":[{"message":"field: phone is restricted on type: Country"}]}`.
Depth and introspection violations answer `403` with
`{"error":"depth limit exceeded"}` / `{"error":"introspection is disabled"}`.

Keyless APIs (and keys with the empty all-APIs access map) get the
API-level checks only.

## Playground

With `"playground": {}` the gateway serves a GraphiQL page on
`{listen_path}/playground` (path configurable). The page sits behind the
API's full middleware chain — on a protected API it requires credentials,
unlike the usual unauthenticated playground. Assets load from a pinned
`cdn.jsdelivr.net` URL, so the browser needs internet access even when
the gateway does not.

## Persisted queries (GraphQL as REST)

`persisted_queries` turns REST-shaped routes into server-side GraphQL
requests:

```json
"persisted_queries": [{
  "method": "GET",
  "path": "/country/{code}",
  "operation": "query C($code: ID!) { country(code: $code) { name } }",
  "variables": { "code": "$path.code", "trace": "$header.x-trace-id" }
}]
```

`GET {listen_path}/country/DE` is rewritten into a `POST` of the operation
to the upstream GraphQL endpoint. In the `variables` template,
`"$path.<name>"` takes the matched `{name}` segment and
`"$header.<name>"` takes a request header (`null` when absent);
substitution recurses into nested objects/arrays, everything else passes
through verbatim. `operation_name` selects one operation when the
document defines several. Persisted operations are validated against the
schema at write/load time and policed per key like any client query.

## Schema sync

`schema_sync` keeps the compiled schema in step with the upstream via
GraphQL introspection (ADR-0008) — periodically, plus immediately on
`POST /g2/graphql/sync` (admin API, broadcast to every pod):

```json
"schema_sync": {
  "interval_ms": 600000,
  "timeout_ms": 10000,
  "url": "http://gql-internal:4000/graphql",
  "headers": { "authorization": "Bearer …" }
}
```

| Field | Default | Meaning |
|---|---|---|
| `interval_ms` | `600000` | Milliseconds between introspection fetches. |
| `timeout_ms` | `10000` | Per-fetch timeout. |
| `url` | the API's upstream | Absolute `http(s)` URL to introspect instead. |
| `headers` | `{}` | Extra headers on the introspection request (upstream auth). |

Each pod POSTs the standard introspection query to the API's upstream
(following load balancing, service discovery, and health eviction; with
`url` set, that pinned endpoint instead), converts the answer to SDL,
compiles it, re-validates every persisted query against it, and swaps the
schema **in memory** — no reload, no storage write. `schema` stays
required: it seeds the state and keeps serving until the first successful
sync (and is what `GET /g2/apis` shows — the synced schema is pod-local).

Failure semantics are stale-on-error: any failure — transport, non-2xx,
an upstream refusing introspection, a schema that does not compile, or a
persisted query invalid against the new schema — keeps the previous
schema serving and surfaces on `GET /g2/node` as a per-API
`graphql_schema_sync` block (`last_success_unix_secs`, `last_error`;
`null` for versioned APIs, which sync per version).

Two things worth knowing: the API's own `introspection_enabled: false`
polices *clients*, not the sync — the fetch goes straight to the
upstream. And an upstream that never answers introspection (the usual
reason for disabling it publicly) leaves the seed schema serving forever
with a permanent `last_error`; that is what the `url` override is for.

## Subscriptions over WebSocket

With `"subscriptions": {}` the listen path also accepts GraphQL WebSocket
handshakes (ADR-0009). The gateway **terminates and polices** the
subprotocol rather than tunneling blindly: every `subscribe`
(graphql-transport-ws) / `start` (legacy graphql-ws) payload is validated
against the schema and run through the same protections as an HTTP query —
depth limits, introspection control, and the key's field permissions.
Violations get a protocol `error` message with the operation's `id` and
never reach the upstream; everything the upstream sends is relayed
verbatim.

```json
"graphql": {
  "schema": "type Query { hello: String } type Subscription { ticks: Int }",
  "subscriptions": { "max_message_bytes": 262144 }
}
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Kill switch inside the block (presence enables, like `playground`). |
| `max_message_bytes` | request-body cap | Cap on one client→gateway WebSocket message; unset inherits the API's `max_request_body_bytes` (1 MiB when that is unset too). |

Worth knowing:

- **Both subprotocols are supported** — `graphql-transport-ws` (the
  `graphql-ws` npm library) and the legacy `graphql-ws`
  (subscriptions-transport-ws). The upstream's `101` picks; an upstream
  that echoes no subprotocol is policed under the union of both. A client
  offering neither is refused at the handshake (`400`), and an upstream
  negotiating anything else gets `502` — the gateway never opens a tunnel
  it cannot police.
- **`enable_upgrades` is not required**: the subscriptions block implies
  upgrade capability for this API. `upstream_http2` cannot be combined
  with it (an HTTP/1.1 upgrade cannot cross an h2-only upstream), and the
  schema must define a `Subscription` root type.
- **The handshake runs the full middleware chain** (it is a `GET`) — auth,
  rate limits, IP filters, analytics. Per-key GraphQL grants are read at
  handshake time and enforced on every operation in the socket.
- **Fail closed**: invalid JSON, unknown message types, binary frames, and
  over-cap messages end the connection (`4400` on graphql-transport-ws; a
  `connection_error` message then `1002` on legacy).
- **A subscription operation over plain HTTP is rejected** with `400`
  (`GraphQL subscriptions require a WebSocket connection`) instead of
  being blind-forwarded — the executed operation is resolved via
  `operationName`, so multi-operation documents selecting a query still
  pass. This applies to every GraphQL API, subscriptions enabled or not.
- Schema sync applies to open tunnels: each operation is validated against
  the schema state current at that moment. Tunnels are not part of the
  graceful drain (expect reconnects on deploys), and there are no
  per-message analytics — the handshake is counted like any request.

## Universal Data Graph

With `"execution_mode": "udg"` (ADR-0010) the gateway executes queries
itself: each requested **root field** (of `Query` or `Mutation`) is
resolved by calling the data source mapped in `data_sources`, and the
results are stitched into one spec-shaped GraphQL response. Nothing is
forwarded — `target_url` stays required but is unused for traffic.

```json
"graphql": {
  "execution_mode": "udg",
  "schema": "type Query { user(id: ID!): User orders: [Order!] } \
             type User { id: ID! name: String } \
             type Order { id: ID! total: Float }",
  "data_sources": {
    "Query.user": {
      "kind": "rest",
      "url": "http://users.internal/users/{{ args.id }}",
      "headers": { "x-caller": "{{ _g2.session.alias }}" }
    },
    "Query.orders": {
      "kind": "graphql",
      "url": "http://orders.internal/graphql",
      "headers": { "authorization": "Bearer …" }
    }
  }
}
```

Every non-meta field of the query and mutation root types must be mapped
(`"<RootType>.<field>"` keys, using the schema's actual root type names) —
an unmapped field is a config error, not a runtime null. Two source kinds:

- **`rest`** — `method` (default `GET`), a templated `url` (the rendered
  result must be absolute `http(s)`), templated `headers` values, and an
  optional templated `body` (sent as `application/json` unless a
  `content-type` header is configured). The response body is parsed as
  JSON and becomes the field's value; nested selections are projected
  from it by **schema field name** (aliases are applied by the gateway,
  unselected JSON is pruned, and abstract-typed values must carry
  `__typename`).
- **`graphql`** — a fixed `url` plus templated `headers`. The gateway
  `POST`s the root field's sub-selection as a standalone query — aliases,
  arguments, referenced fragments, and the variable definitions the
  subtree uses all round-trip — with the client's variables filtered to
  that subset. The response's `data` is merged in; its `errors` are
  appended to the stitched response (message-only, prefixed with the
  source key).

Templates are minijinja (the body-transform engine, ADR-0007),
fuel-bounded and compiled at route-build time. The context is
`{ args, _g2 }`: `args` are the field's coerced GraphQL arguments
(variables substituted, defaults applied), `_g2` carries
`method`/`path`/`query`/`headers` (lowercase name → first value) and
`session.alias`.

Per source, `timeout_ms` defaults to the API's `upstream_timeout_ms` and
`max_response_bytes` to 4 MiB. A query's sources are fetched
**concurrently**; a mutation's serially, in selection order (spec
execution order).

Worth knowing:

- **Failures are per-field**: a source that cannot be reached, times out,
  answers non-2xx, over-caps, or returns invalid JSON becomes a GraphQL
  field error (with `path`) and a `null` — the rest of the query still
  answers, HTTP `200`, per the spec. Error messages name only the source
  key (`Query.user`); URLs, statuses, and bodies go to the gateway log.
  Request-level failures (unknown `operationName`, bad `variables`,
  variable-coercion errors) are `400`.
- **Every protection still runs first**: auth, rate limits, depth limits,
  introspection control, and per-key field grants reject *before* any
  source is fetched. Introspection (`__schema`/`__type`) is answered by
  the gateway from the compiled schema with zero upstream traffic.
- **Persisted queries and the playground work unchanged** — persisted
  operations execute locally through the same engine.
- **`schema_sync` and enabled `subscriptions` are rejected** in udg mode
  (there is no single upstream to introspect; streaming execution is a
  later box). A `subscriptions` block with `"enabled": false` may stay.
- Data-source fetches bypass the proxy path: load balancing, service
  discovery, health eviction, retries, and the circuit breaker do not
  apply to them (per-source resilience is future work).
- Data-source templates are minijinja: `{{ args.id }}` interpolates a
  field argument. Shape the schema to the REST response — there is
  no `data_path` remapping yet.

## Interactions and limits

- **Body buffering**: GraphQL POSTs are buffered to be parsed, capped at
  the API's `max_request_body_bytes` (1 MiB when unset); over the cap is
  `413`. The exact original bytes are forwarded, so the upstream sees the
  request unmodified.
- **Caching**: the response cache only stores safe methods, so GraphQL
  POSTs are never cached. GraphQL-aware caching is a later M9 box.
- **Introspection depth**: a pure introspection query (only `__`-fields
  at the root) bypasses the depth limit when introspection is allowed —
  tooling sends deep introspection documents.
- **Methods**: a GraphQL API answers `GET` and `POST`; other methods get
  `405` (CORS preflights are handled by the CORS layer above).
- **Not yet**: federation, APQ, request batching, GraphQL-aware caching,
  nested-field (non-root) UDG data sources — all tracked as M9 roadmap
  boxes.
