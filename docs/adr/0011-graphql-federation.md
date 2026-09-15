# ADR-0011: GraphQL federation (supergraph & subgraph)

Date: 2026-09-02 · Status: accepted

## Context

Apollo Federation splits one graph across services: each *subgraph* owns a
slice of the schema and marks shared object types as *entities* with
`@key`; a router composes the subgraph schemas into one *supergraph* and
answers cross-subgraph selections by fetching entity fields from their
owners via the reserved `_entities(representations: [_Any!]!)` field. A
gateway can play both roles: a *subgraph API* fronts one federation-capable
service, and a *supergraph API* composes subgraph APIs and executes
federated queries. ADR-0010 built the execution engine this needs (apollo-compiler's
`resolvers::Execution` run in record/fetch/stitch phases, the `UdgFetch`
HTTP seam); this ADR decides how federation rides it. Deliberately v1: the
goal is correct execution of the common federation shape (flat scalar keys,
object-type entities), not apollo-router parity.

## Decisions

1. **Two new execution modes on the existing enum: `subgraph` and
   `supergraph`.** ADR-0010 §2's reasoning holds: both are branches inside
   `GraphQlLayer`, not new chain slots. Every existing GraphQL protection
   (parse, validation, depth, introspection control, per-key field
   permissions) runs unchanged in both modes, against the mode's *effective*
   schema (decision 2/3).

2. **`subgraph` mode is proxy mode with a federation-aware schema.** The
   configured `graphql.schema` is the subgraph SDL (with `@key` etc.); the
   gateway augments it at build time — injecting any missing federation
   directive/scalar definitions (`@key`, `@external`, `@requires`,
   `@provides`, `@shareable`, `@extends`, `@override`, `@inaccessible`,
   `@tag`, `@link`, `_FieldSet`, `_Any`, `_Service`) plus the reserved root
   fields (`_service: _Service!` and, when the SDL declares entities,
   `_entities(representations: [_Any!]!): [_Entity]!` with the `_Entity`
   union) — and polices requests against the augmented schema, so a
   federating router's `_entities`/`_service` queries validate and are
   forwarded like any other operation. The upstream must itself implement
   the federation service spec (the gateway forwards, it does not answer
   `_service`); injection is skipped for definitions the SDL already
   carries, so a full federation-expanded SDL (e.g. from schema sync
   introspection) round-trips. Considered: answering `_service { sdl }`
   gateway-side (rejected — the SDL the *upstream* serves is authoritative
   for composition; serving a second copy invites drift), a separate
   `federation: true` flag on proxy mode (rejected — modes are the
   established axis, and supergraph mode needs the same prelude machinery).

3. **`supergraph` mode composes at config time and executes at the
   gateway.** `graphql.supergraph.subgraphs` lists `{name, url, sdl,
   headers, timeout_ms, max_response_bytes}` — the subgraph SDL is pasted
   into the definition (like `graphql.schema` always has been) rather than
   fetched, so composition is deterministic and write-time-validated; a
   g2way subgraph API is referenced by its gateway URL. `graphql.schema`
   must be **empty** in this mode (it gains `#[serde(default)]`): the
   composed schema is derived, never authored, and is what clients see via
   introspection and the playground. Composition failures are
   write/load-time errors (the house rule: loud validation, nothing
   dormant). Considered: referencing subgraph APIs by `api_id` (rejected
   for v1 — cross-definition resolution creates load-order coupling that
   ADR-0002's merge semantics deliberately avoid), fetching SDLs from the
   subgraphs' `_service` at build (rejected — route builds must not do
   network I/O, and a reload would compose whatever the network says that
   second).

4. **Composition is a pragmatic v1 merge, in `g2-core::federation`, with
   loud errors instead of silent precedence.** Rules: root types must be
   named `Query`/`Mutation`; a root field defined by two subgraphs is an
   error (no `@shareable` root fields in v1). An object type with `@key` in
   any defining subgraph is an entity: its composed fields are the union
   across subgraphs, a field's *owners* are the subgraphs defining it
   non-`@external`, and duplicate definitions must agree on type and
   arguments. Non-entity types defined by several subgraphs are value types
   and must be structurally identical (fields, types, arguments; enum
   values; union members). Federation directives are stripped from the
   composed schema, and the composed SDL is re-validated with
   apollo-compiler as a final gate. `@requires` and `@override` are
   composition errors in v1 (unsupported, not misexecuted); `@provides` is
   ignored (correct but unoptimized: the owner is fetched even when a
   provider already returned the field). Keys: the **first** `@key` of each
   subgraph's entity definition is that subgraph's canonical key; v1 keys
   are flat scalar field lists (no nested selections), and composition
   verifies every subgraph that can *return* an entity defines the key
   fields every *owner* needs (so representations are always collectable).
   Considered: shipping apollo's own composition (rejected — it lives in
   JS/rover, not a Rust library), accepting a pre-composed supergraph SDL
   (rejected — join-spec directives are a bigger parsing surface than v1
   composition itself).

5. **Execution extends the ADR-0010 three-phase engine with iterative
   entity resolution.** The record pass is unchanged. A new *planning*
   walk splits each recorded root field's selection tree by ownership:
   fields resolvable by the current fetch's subgraph print into its
   sub-query; a field on an entity type owned elsewhere becomes a *child
   fetch* (grouped per target subgraph per selection set), and the parent's
   printed selection gains `__typename` plus the target's key fields. The
   fetch phase runs each root field's plan: fetch the owner
   (concurrently across query root fields, serially for mutations), then
   per level collect representations from the returned JSON (walking the
   recorded response-key path, filtering by `__typename` under inline
   fragments, skipping nulls and objects missing key fields), POST one
   `_entities` query per child fetch (`query ($representations: [_Any!]!,
   …used variables) { _entities(representations: $representations)
   { ... on T { … } } }`), resolve grandchildren against the returned
   entity values, and merge each entity object's fields back into its
   representation's source object in order. The stitch pass is ADR-0010's,
   keyed by response key. `__typename` is injected into every printed
   selection set, which also satisfies the stitch pass's abstract-type
   requirement without demanding upstream cooperation. Fragment spreads are
   inlined into the printed sub-queries (as `... on T`), so subgraphs never
   need the client's fragment definitions; each fetch carries only the
   variable definitions and values its subtree uses (ADR-0010 §4).
   Considered: a full apollo-router-style query planner with fetch-group
   batching per subgraph (rejected for v1 — the per-root/per-level plan is
   spec-correct and orders of magnitude simpler; batching root fields per
   subgraph is a future optimization).

6. **Fetches ride the `UdgFetch` seam; subgraph headers are static
   values.** Same trait, same g2-proxy implementation over the shared h1
   pool, same caps (per-subgraph `timeout_ms` defaulting to the API's
   `upstream_timeout_ms`, `max_response_bytes` defaulting to 4 MiB).
   Subgraph `headers` are literal values (the `schema_sync.headers`
   precedent — upstream auth), not minijinja templates: there are no field
   arguments at the subgraph level to template with. Failure semantics are
   ADR-0010 §7: a subgraph failure becomes field errors naming only the
   subgraph name (detail logged); a failed `_entities` fetch leaves its
   entity fields unmerged, so the stitch pass nulls them per nullability
   with positioned errors; upstream GraphQL errors are appended
   message-only.

7. **Supergraph mode rejects `schema_sync`, enabled `subscriptions`, and
   `data_sources` at validation — the ADR-0010 §10 reasoning verbatim.**
   Consequence: the schema leaf never swaps, so the compiled
   `SupergraphEngine` (ownership tables, keys, printed-prelude state)
   lives schema-independent in `GraphQlShared` beside the UDG engine; still
   no third swappable leaf. Subgraph mode keeps proxy-mode freedoms:
   schema sync (a federation-capable upstream's introspection includes the
   reserved types, and augmentation is idempotent) and subscriptions both
   work.

8. **`target_url` stays required and unused for supergraph traffic**
   (ADR-0010 §9's trade-off, unchanged). Subgraph mode forwards to it like
   any proxy-mode API.

## Consequences

- The gateway executes federated queries without apollo-router: N+1 entity
  fetches are bounded by query depth (one `_entities` round per ownership
  boundary per level), sibling fetches run concurrently, and denied/invalid
  queries still never reach any subgraph.
- v1 limits, all loud at composition or documented: flat scalar keys only;
  no `@requires`/`@override`; `@provides` unoptimized; no `@shareable`
  root fields; entity cuts only on object types (an interface field owned
  elsewhere composes but cannot be cut); value types must match exactly;
  root types must be `Query`/`Mutation`. Interface entities,
  `@interfaceObject`, and federated subscriptions are future boxes.
- Ignoring `@provides` and injecting `__typename`+keys means slightly
  larger subgraph responses than an optimal planner would request.
- Clients of a supergraph API see the composed, federation-directive-free
  schema in introspection and the playground; per-key field permissions
  and depth limits apply to it like any schema.
- Supergraph composition takes inline `{name, url, sdl}` subgraph entries
  rather than references to other API definitions.
- No new dependencies anywhere: apollo-compiler (g2-core, g2-middleware)
  and the existing fetch seam carry everything.
