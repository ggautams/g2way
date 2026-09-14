# Request/response body transforms

g2way can rewrite the body of matching requests and responses with
[minijinja](https://docs.rs/minijinja) (Jinja2-syntax) templates — the
gateway's body transform middleware:

- **Request rules** rewrite the upstream-bound body before forwarding.
- **Response rules** rewrite the client-bound body — upstream responses,
  mock responses and cached responses alike.
- Rules are endpoint-scoped (regex + methods, first match wins) and
  templates are inline in the API definition — no file/blob mode.
- Transforms **fail closed**: an over-cap body or a failing render rejects
  the exchange instead of passing the original body through.

Design decisions live in [ADR-0007](adr/0007-body-transforms.md).

## Configuration

Each API opts in with a `transform_body` block:

```json
{
  "api_id": "orders",
  "name": "Orders API",
  "listen_path": "/orders/",
  "target_url": "http://orders.internal:8000/",
  "auth": { "mode": "auth_token" },
  "transform_body": {
    "request": [
      { "pattern": "^/orders/submit$",
        "methods": ["POST"],
        "template": "{\"order\": {{ body | tojson }}, \"submitted_by\": {{ _g2.session.alias | tojson }}}" }
    ],
    "response": [
      { "pattern": "^/orders/",
        "template": "{\"data\": {{ body | tojson }}, \"proxied\": true}" }
    ],
    "max_response_body_bytes": 1048576
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `request` / `response` | `[]` | Rule lists, tried in order; the first match per direction wins. A present `transform_body` block must declare at least one rule. |
| `pattern` | — | Required. Regex searched (unanchored) against the **full client request path**, listen path included — for response rules too: a transform targets an endpoint, not a status code. |
| `methods` | `[]` | Methods the rule applies to (case-insensitive). Empty = every method. |
| `template` | — | Required. The minijinja template whose rendered output replaces the body. Syntax-checked when the definition is validated. |
| `content_type` | `application/json` | `Content-Type` set on the transformed message. |
| `max_response_body_bytes` | `1048576` (1 MiB) | Cap on a buffered upstream response body; a matching response larger than this is rejected with `502`. |

Request bodies are capped by the API's `max_request_body_bytes` (1 MiB when
unset); a matching request over that cap is rejected with `413`.

`VersionOverrides.transform_body` replaces the whole block for that version
(rule lists and response cap together — omit the override to inherit).

### Template context

| Name | Meaning |
|---|---|
| `body` | The buffered payload parsed as JSON; `none` when it does not parse (test with `{% if body %}`). Response rules see the upstream response body here. |
| `raw` | The payload as text (lossy UTF-8), always present — wrap non-JSON payloads with `{{ raw | tojson }}`. |
| `_g2.method` | The client request method (`"POST"`). |
| `_g2.path` | The full client request path. |
| `_g2.query` | The raw query string (empty when absent). |
| `_g2.headers` | Request headers: lowercase name → first value. |
| `_g2.session` | `{ "alias": … }` for authenticated requests, `none` for keyless/ignored ones. |
| `_g2.status` | Response rules only: the upstream status code as a number. |

Emit JSON values with the `tojson` filter — bare interpolation renders
Jinja-style (`{{ true }}` prints `True`, strings print unquoted), while
`{{ value | tojson }}` always produces valid JSON.

### Semantics

- **Fail closed.** A failing render answers `500` (request side) or `502`
  (response side); an over-cap body answers `413`/`502` as above. The
  original body is never passed through on failure — transforms are often
  used to redact, and failing open would leak exactly what the
  configuration exists to remove. Failures are logged with the API id and
  rule. Rendering is pure computation bounded by a fuel limit (a runaway
  template errors deterministically); there is no timeout.
- **Gateway rejections are not transformed** (401/403/429 and friends keep
  their bodies), matching header-transform semantics. **Mock responses are
  transformed**, and the response cache stores the raw upstream body with
  transforms re-applied on every hit — also matching header transforms.
- **JSON input only.** A non-JSON (or compressed — the gateway does not
  decompress) payload renders with `body` as `none`; use `raw`. There is
  no XML mode.
- **Framing is made truthful.** The rebuilt message carries the rule's
  `content_type`, an exact `Content-Length`, and drops
  `Transfer-Encoding`/`Content-Encoding` — the rendered text is neither
  chunked nor compressed.
- **Header transforms run outside body transforms**: on requests a body
  rule's `content_type` wins over a header-transform `add`; on responses a
  header-transform `add` wins.
- **`1xx` responses are never transformed**, so upgrade handshakes
  (WebSocket APIs with `enable_upgrades`) tunnel through undisturbed.
- **Don't point a response rule at a streaming endpoint.** A matching
  response is buffered whole; an SSE stream never completes, so the
  request holds until the cap trips a `502`. Path-scope response rules
  away from streaming endpoints (the same caveat as `cache`).
- **Trailers survive.** A transformed response re-emits the upstream's
  trailer frames, so `grpc-status` on an `upstream_http2` API stays
  intact — though transforming protobuf payloads is not meaningful;
  path-scope rules to JSON endpoints.
- **Retries are unchanged.** A transformed request body is a buffered,
  replayable body, but the forwarder's retry gate (idempotent method +
  un-started body) is deliberately untouched (ADR-0007).

## Verification

With `make httpbin-up` and an API like the example above pointed at
httpbin (`make run`):

```sh
# Request transform: httpbin echoes what it received.
curl -s -X POST 'http://127.0.0.1:8080/orders/submit' \
  -H 'Authorization: <key>' -d '{"id": 1}' | jq .json
# → { "order": { "id": 1 }, "submitted_by": "<alias>" }

# Response transform: the client sees the reshaped envelope.
curl -s 'http://127.0.0.1:8080/orders/anything' -H 'Authorization: <key>'
# → {"data": …, "proxied": true}

# Oversized matching request (with "max_request_body_bytes": 64):
head -c 100 /dev/zero | curl -s -X POST --data-binary @- \
  'http://127.0.0.1:8080/orders/submit' -H 'Authorization: <key>' -w '%{http_code}'
# → 413
```

The e2e suite (`crates/g2way/tests/transform_body_e2e.rs`) drives all four
paths — request rewrite, response rewrite, untouched passthrough, 413 —
through a real gateway and upstream.
