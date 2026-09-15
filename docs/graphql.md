# GraphQL

g2way can front a GraphQL upstream as a policing proxy (`proxy` mode):
every request is parsed as GraphQL, validated against a schema you
configure, and checked against depth limits, introspection rules, and
per-key field permissions **before** it reaches the upstream. The gateway
never executes GraphQL itself — valid, permitted requests are forwarded
byte-for-byte.

Design decisions live in [ADR-0004](adr/0004-graphql.md). A runnable
example definition is `examples/apis/graphql.json`.

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
| `execution_mode` | `"proxy"` | Only `proxy` today (UDG/federation are later M9 work). |
| `schema` | — (required) | The GraphQL schema, SDL. Validated at write/load time; requests are validated against it. |
| `introspection_enabled` | `true` | `false` rejects `__schema`/`__type` queries with `403`. |
| `max_query_depth` | unlimited | Nested selection-set levels (`{ a { b } }` = 2); deeper queries get `403`. |
| `playground` | off | Serve a GraphiQL page (see below). |
| `persisted_queries` | `[]` | GraphQL-as-REST endpoints (see below). |
| `schema_sync` | off | Keep the schema in sync with the upstream via introspection (see below). |
| `subscriptions` | off | GraphQL subscriptions over WebSocket, policed message by message (see below). |

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
- **Not yet**: UDG/federation, APQ, request batching — all tracked as M9
  roadmap boxes.
