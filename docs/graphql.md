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
- **Not yet**: subscriptions (needs WebSocket passthrough), schema sync
  from upstream introspection, UDG/federation, APQ, request batching —
  all tracked as M9 roadmap boxes.
