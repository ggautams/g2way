# ADR-0007: Request/response body transforms (minijinja)

Date: 2026-09-01 · Status: accepted

## Context

The last M8+ box is body transform middleware: per-endpoint
templates that rewrite a request body before it reaches the upstream and a
response body before it reaches the client. This is the first feature that
must buffer **response** bodies (the GraphQL layer buffers requests only),
which bends ADR-0001's everything-streams assumption, and it introduces a
template engine — a new third-party dependency executing operator-supplied
programs on the hot path. The engine choice (minijinja) was made and
user-confirmed when the service-discovery box was split off.

## Decisions

1. **Engine: minijinja 2, trimmed features.** Pure Rust, MSRV 1.70 (fits
   the workspace's 1.85), no build script (the `rust:1-slim` Docker stage
   stays cmake-free), serde-native values, and templates compile to
   programs once at insert time. Features: `builtins` + `serde` + `json`
   (the `tojson` filter — the correct way to emit JSON from a template) +
   `fuel` (decision 4); deliberately **not** `multi_template`, so
   `include`/`extends` are config-time syntax errors and every template is
   self-contained. Considered: **tera** (heavier, pulls chrono and a
   slower release cadence), **handlebars** (logic-less enough to make
   reshaping awkward), and Go-style text/template syntax (no Rust
   implementation; users get Jinja2 syntax instead).

2. **Endpoint-scoped rules with inline templates.**
   `transform_body.{request,response}: [{pattern, methods, template,
   content_type}]` plus `max_response_body_bytes` — the `mock_responses`
   shape (full-client-path regex, empty methods = all, first match wins),
   not an `extended_paths` block with base64 template blobs or file
   references. Inline-only keeps definitions self-contained across the
   file and Redis sources (a file path would break the storage source);
   response rules match on the *request's* method and path — a transform
   targets an endpoint, not a status class. Templates are syntax-checked
   at validation time (a throwaway parse), compiled into one long-lived
   `Environment` per API at route-build time, and rendered by name per
   request — the hot path never parses (ADR-0001). Per-version:
   `VersionOverrides.transform_body` replaces the block wholesale, like
   every other override.

3. **Named-key template context, JSON input only.** Templates see `body`
   (the payload parsed as JSON, `none` when it does not parse), `raw`
   (lossy UTF-8 text, always present) and `_g2` (method, path, query,
   lowercase request headers, session alias, response status) — not a
   body-at-root merge, which cannot represent array/scalar/unparseable
   bodies and invites key collisions with context names. No XML input
   mode, and no decompression: a compressed upstream body simply renders
   with `body = none`. The `_g2` prefix namespaces gateway metadata so it
   cannot collide with payload keys.

4. **Bounded buffering, fail closed, fuel instead of timeouts.** A
   matching request body is collected through `Limited` capped by the
   API's `max_request_body_bytes` (1 MiB default; over → `413`, reusing
   the GraphQL layer's error mapping); a matching response body is capped
   by `max_response_body_bytes` (1 MiB default; over → `502`). A failing
   render answers `500` (request) / `502` (response). Failing **closed**
   inverts the rate limiter's fail-open stance for the same reason the
   plugin system did (ADR-0005 §4): transforms are used to redact, and
   passing the original body through on failure leaks exactly what the
   configuration exists to remove. Rendering is pure computation — no
   I/O, no clock — so instead of ADR-0005's epoch-ticker machinery a
   minijinja fuel budget (1M units) plus the built-in recursion limit
   bound a pathological template deterministically.

5. **Chain slot 16, directly below the header transforms; scoped
   ADR-0001 amendment.** Gateway rejections stay untransformed while
   mocks and cache hits are transformed, exactly like header transforms
   (the stored cache copy stays the raw upstream body). The amendment:
   *response bodies of matching endpoints only* are buffered — all other
   traffic, and every non-matching path on a transforming API, streams
   untouched. `1xx` responses are structurally skipped (upgrade tunnels
   undisturbed; no validation conflict with `enable_upgrades`, since
   rules are path-scoped). Upstream trailers are re-emitted after a
   response transform (`grpc-status` survives `upstream_http2` APIs).
   The forwarder's retry gate is deliberately unchanged, mirroring
   ADR-0004 decision 4: a transformed request body is technically
   replayable, but widening retry eligibility is its own decision.

## Consequences

- A response rule pointed at a streaming (SSE) endpoint buffers until the
  cap answers `502`; documented, like the cache's SSE caveat.
- Templates are Jinja2: a field of the parsed body is `{{ body.field }}`,
  not a bare `{{.field}}`.
- Bare interpolation renders Jinja-style (`True`, unquoted strings); the
  docs steer every JSON-emitting template to `| tojson`.
- Template file references, XML input, gateway-side decompression and
  per-rule response caps are all future refinements, none of which
  breaks the config shape.
- g2-core now compiles minijinja (validation parse); the proxy path's
  dependency tree is otherwise unchanged.
