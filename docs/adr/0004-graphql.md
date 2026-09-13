# ADR-0004: GraphQL proxy mode and protections

Date: 2026-08-31 · Status: accepted

## Context

M9 targets a full GraphQL feature set: four execution modes (pass-through
proxy, Universal Data Graph, federation supergraph/subgraph) plus a
protection suite: query validation against a stored schema, depth limits,
per-key field permissions, introspection control, a gateway-served
playground, and persisted GraphQL-as-REST endpoints. Depth limiting is the
only GraphQL DoS control in this milestone (no cost/complexity scoring —
that is a stretch box), and all per-key GraphQL grants ride on the
session's access rights, which maps directly onto g2way's
`KeySession.access` map.

This slice implements the proxy mode and the full protection suite. It is
also the first g2way feature that must **parse a request body**, which
forces decisions about buffering and retry semantics.

## Decisions

1. **GraphQL parsing/validation uses `apollo-compiler` (apollo-rs).**
   `Schema::parse_and_validate` compiles the SDL once at route-build time;
   `ExecutableDocument::parse_and_validate` gives spec-compliant validation
   of each request against that schema (unknown fields/types rejected,
   fragment cycles impossible afterwards) plus a typed selection tree that
   carries the parent type name per selection set — exactly what the depth
   and field-permission walks need. Pure Rust (no cmake; the distroless
   Docker build is unaffected), maintained by Apollo, powers Apollo Router.
   Considered: `async-graphql` (a server framework whose validation is
   coupled to its own runtime schema — far too heavy for a proxy),
   `apollo-parser`/`graphql-parser` alone (schema validation would be
   hand-rolled; graphql-parser is near-unmaintained).

2. **The schema lives in the API definition** (`graphql.schema`, SDL) and
   is validated wherever definitions are validated — admin writes and file
   loads fail loudly on a broken schema, never at request time. This adds
   apollo-compiler to `g2-core`, the one deliberate weight put on the leaf
   crate; the alternative (validate only in the middleware at route-build)
   would let `POST /g2/apis` accept a schema that later fails the reload.
   Schema sync from upstream introspection is a separate M9 box, not this
   slice.

3. **One `GraphQlLayer`, placed between `RateLimitLayer` and
   `HeaderTransformLayer`.** Playground serving, persisted-query rewriting,
   and the protection pipeline share the compiled schema, the session
   lookup, and the listen-prefix math, so they are one layer rather than
   three. Below auth and rate limiting: the protections need the key's
   grants, the playground stays credentialed (it runs the full auth
   chain), and rejected requests never buy parse work. Above
   the transforms: GraphQL rejections stay untransformed like every other
   gateway rejection, and the persisted rewrite happens before request
   transforms see the upstream-bound request.

4. **Request bodies are buffered, bounded, and re-emitted verbatim.** The
   POST body is collected through `http_body_util::Limited`, capped at the
   API's `max_request_body_bytes` (1 MiB when unset), and forwarded as the
   exact original bytes — the upstream sees the request unmodified,
   `Content-Length` stays truthful. A `RequestTooLarge` from the
   size-limit layer's counting body surfaces in this collect instead of in
   the forwarder; the layer downcasts for it (and for its own cap) and
   answers `413`, mirroring the forwarder's handling. **Retry semantics
   are deliberately unchanged**: the buffered `Full` body is technically
   replayable, but the forwarder's retry gate (idempotent method +
   `is_end_stream`) stays as is — GraphQL rides POST, and widening retry
   eligibility is its own future decision, not a buffering side effect.

5. **Per-key grants extend `ApiAccess`** (`allowed_types`,
   `restricted_types`, `disable_introspection`, `max_query_depth`) — the
   deliberately-empty per-API grant struct reserved for exactly this. Old
   `{}` records keep parsing and mean "unrestricted"; policies inherit the
   grants for free because `Policy.access` is the same map, cloned
   wholesale at auth time. Grant semantics: a non-empty allow
   list is exhaustive and wins over the block list, `"*"` matches every
   field of its type, key depth `-1` lifts the API limit.

6. **Error shapes are deliberately mixed, per rejection class.** Depth and
   introspection rejections: `403` with the gateway's plain
   `{"error": …}`. Parse/validation and field-permission rejections:
   `400` with GraphQL-style `{"errors": [{"message": …}]}` (field
   violations use the
   `field: <f> is restricted on type: <T>` message). Mixed, but each class
   answers in the shape its callers parse. A pure introspection
   document bypasses depth/field checks when introspection is allowed —
   tooling sends deep introspection queries, and the schema is exactly
   what introspection reveals.

7. **Out of scope, recorded as M9 boxes:** subscriptions (blocked on
   WebSocket upgrade passthrough, an existing M8+ box), schema sync from
   upstream introspection, UDG/federation (needs an execution-engine ADR),
   GraphQL-aware caching, cost-based complexity limits, APQ, and request
   batching (a batched JSON array is rejected as an invalid envelope).

## Consequences

- Per-request GraphQL parsing is payload work, not configuration work —
  ADR-0001's "requests never parse configuration" rule stands; everything
  derivable from config (compiled schema, playground HTML, persisted-path
  regexes, pre-parsed persisted operations) is built at route-build time.
- APIs without a `graphql` block get no layer in their chain and pay
  nothing.
- The playground page loads GraphiQL from a pinned CDN
  (`cdn.jsdelivr.net`); air-gapped deployments need a bundled-asset
  follow-up before the playground is usable offline.
- `ApiAccess` is no longer `Copy` (it carries `Vec`s now).
- GraphQL responses are never cached by the response cache (it only
  caches safe methods, and GraphQL traffic rides POST); GraphQL-aware
  caching is its own roadmap box.
