# Per-endpoint rate limits (API-level)

`endpoint_rate_limits` caps traffic to specific endpoints of one API,
**aggregate across all clients** — the API-level flavor of endpoint rate
limiting. Where key-session rate limits protect against one consumer
misbehaving, endpoint limits protect an expensive upstream operation (a
search, an export, a webhook receiver) from everyone combined. Because the
counters are not tied to any session, they also work on keyless APIs and on
`ignore_auth_paths` matches — the two places that previously had no rate
limiting at all.

## Configuration

```json
{
  "api_id": "users",
  "name": "Users",
  "listen_path": "/users/",
  "target_url": "http://users.internal:8000",
  "auth": { "mode": "keyless" },
  "endpoint_rate_limits": [
    { "pattern": "^/users/search", "methods": ["POST"],
      "rate": { "requests": 10, "per_seconds": 60 } },
    { "pattern": "^/users/export$",
      "rate": { "requests": 2, "per_seconds": 3600 } }
  ]
}
```

| Field | Default | Meaning |
|---|---|---|
| `pattern` | required | Regex searched (unanchored — anchor with `^`/`$`) against the **full client request path, listen path included**, like every other path rule: match `^/users/search`, not `^/search`. |
| `methods` | `[]` (all) | Methods the rule applies to, case-insensitive. |
| `rate.requests` | required | Matching requests admitted per window, all clients combined. Zero is rejected at validation — omit the rule for unlimited. |
| `rate.per_seconds` | required | The sliding window length in seconds. |

Rules are tried in order and **the first match wins**: only that rule's
counter is checked and consumed, even when a later rule also matches (same
semantics as `mock_responses`). Order specific patterns before general ones.

The window is the same sliding-window log the session rate limiter uses
(counters shared across all gateway pods via Redis), and a denial is the
same `429` with `X-RateLimit-Limit`/`-Remaining`/`-Reset` (absolute Unix
seconds) and `Retry-After` headers — indistinguishable from a session-rate
denial, deliberately.

```sh
for i in 1 2 3; do
  curl -si http://gateway:8080/users/export | head -1
done
# HTTP/1.1 200 OK
# HTTP/1.1 200 OK   (requests: 2 in the example above)
# HTTP/1.1 429 Too Many Requests
```

## Interaction with session limits

Endpoint limits are checked **before** every session check (spike guard,
key rate, quota):

- A request denied by an endpoint limit consumes none of the caller's
  session rate or quota.
- A request the endpoint limit admits but a session limit then denies does
  occupy an endpoint slot for its window (mirrors how a rate-admitted,
  quota-denied request occupies a rate slot).
- The pod-local spike guard covers only the session checks; endpoint checks
  always go to storage.

Mocks, GraphQL handling, and the response cache all sit below the limiter,
so endpoint limits gate them too — a cache hit or mocked endpoint still
consumes its slot, exactly like session limits today.

## Versioning

`endpoint_rate_limits` can be overridden per version (replaced wholesale;
`[]` disables limits for that version). Each version counts under its own
scope, so versions never share allowances.

## Operational notes

- Counters live at `g2:{org}:endpointrl:{scope}:{index}` (`scope` = api id,
  or `{api_id}:{version}`), keyed by the rule's **position in the list** —
  reordering or inserting rules re-binds counters, resetting the affected
  windows. Harmless for short windows; worth knowing for hour-scale ones.
- **Fail-open** on storage errors, like every limiter check: limits protect
  capacity, they are not authorization.

## Limits

- Aggregate only: per-key/per-session endpoint limits (a key-level
  `access_rights[].endpoints` flavor) are future work.
- No per-client fairness within an endpoint's allowance — one chatty client
  can exhaust it for everyone. That is the semantics of an aggregate cap;
  pair it with session rate limits on protected APIs if fairness matters.
