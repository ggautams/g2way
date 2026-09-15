# ADR-0008: GraphQL schema sync from upstream introspection

Date: 2026-09-02 · Status: accepted

## Context

ADR-0004 put the GraphQL schema (SDL) in the API definition and compiled it
once at route-build time; requests are validated against that snapshot.
When the upstream's schema evolves, the gateway's copy goes stale and
starts rejecting valid queries until an operator hand-edits the definition.
Operability wants sync: the gateway fetches the schema
from the upstream via GraphQL introspection, periodically and on an admin
trigger. That collides with ADR-0001 §4 the same way service discovery did:
the compiled schema lives inside an immutable route.

## Decisions

1. **Pod-local, in-memory sync — no storage write-back.** Each pod's sync
   task swaps its own compiled schema; the `graphql.schema` SDL in the
   definition stays **required** and seeds the state (the fallback until
   the first successful sync, and the schema of record for `GET /g2/apis`).
   Considered instead: writing the introspected SDL back into the stored
   `ApiDefinition` and nudging a reload. Rejected: it cannot work for
   file-sourced definitions (a storage record would collide with the file
   def under ADR-0002's merge rules), periodic multi-pod writers would race,
   and a full table rebuild per schema change re-runs every layer's config
   work for a one-leaf change. Consequence: the SDL served by admin reads
   is the seed, not the synced schema.

2. **Second scoped amendment to ADR-0001 §4: the schema state is a
   designated swappable leaf.** `GraphQlShared` now holds
   `ArcSwap<GraphQlSchemaState { sdl, schema, persisted_docs }>`; a
   successful sync swaps that leaf wholesale and touches nothing else.
   The persisted GraphQL-as-REST operations' pre-parsed documents live
   *inside* the swapped state (index-parallel to the schema-independent
   compiled endpoints) because they are validated against the schema —
   the TargetSet/HealthState precedent from ADR-0006 §3, applied to
   documents. The hot path pays one wait-free `load_full()` per GraphQL
   request (the Arc is held across awaits; guards are never held).
   Playground HTML, persisted-path regexes, and key-level field grants are
   schema-independent and untouched by a swap (grants are name-matched — a
   type that vanishes simply never matches).

3. **Hand-written introspection→SDL emitter, one validation entry point.**
   apollo-compiler serializes schemas but has no introspection-JSON import,
   and no crate in the tree offers one, so `introspection_to_sdl`
   (g2-middleware) is a pure serde_json→String conversion of the canonical
   introspection response. The produced SDL then goes through the *same*
   `Schema::parse_and_validate` path config validation uses — a converter
   gap fails the sync (stale schema, recorded error), never produces a
   half-broken schema. The emitter skips built-in types/scalars/directives
   (redeclarations fail validation) and drops argument descriptions (a
   documentation-only loss). The introspection query sent upstream omits
   `specifiedByURL`/`isRepeatable` for older-server compatibility.

4. **Stale-on-error, including persisted re-validation.** Any failure —
   transport, timeout, non-2xx, body over the 4 MiB cap, non-introspection
   JSON (an upstream with introspection disabled answers `errors`), SDL
   that does not compile, or **any persisted operation invalid against the
   new schema** — keeps the previous state serving, records the error for
   `GET /g2/node`, and retries next tick. A persisted-query failure fails
   the *whole* sync (not just that endpoint): a schema that breaks a
   configured endpoint is treated as not-yet-deployed, mirroring how
   definition validation would refuse it. An *unchanged* SDL is a recorded
   success that swaps nothing (no churn, pointer-equal state).

5. **Fetching follows traffic; a pinned URL is a side channel.** Without
   `schema_sync.url`, the introspection `POST` goes to the API's own
   upstream through `client_for` (speaking `upstream_http2` like health
   probes) at an address derived per fetch from `next_addr()` — load
   balancing, discovery swaps, and health eviction steer introspection
   like they steer traffic, and the request bypasses the gateway's own
   chain (the API-level `introspection_enabled: false` polices *clients*,
   not the sync). With `schema_sync.url`, the fetch rides the HTTP/1.1
   pool like JWKS/discovery — the escape hatch for upstreams that serve
   introspection on an internal endpoint only. `schema_sync.headers`
   carries upstream auth either way.

6. **Admin trigger is a pub/sub nudge, coalesced per pod.** `POST
   /g2/graphql/sync` publishes on `g2:{org}:channel:graphql-sync`
   (`reload_channel` precedent: payload-free, best-effort); each pod's
   listener walks the current route snapshot and `trigger()`s every synced
   version's handle. The trigger is a `Notify` permit — concurrent nudges
   while a fetch is in flight coalesce into one follow-up fetch, so no
   JWKS-style cooldown is needed (only admins can nudge). Lifecycle is
   Weak-based like every refresher: the task exits on its first wakeup
   after the route table drops, and while waiting it holds only a detached
   nudge listener (never the schema state).

## Consequences

- Two designated swappable leaves now exist (`TargetSet`, ADR-0006; the
  GraphQL schema state, this ADR). The bar for a third stays high:
  wholesale-swap of one precomputed leaf, never in-place mutation.
- `GET /g2/node` reports a `graphql_schema_sync` status block
  (`last_success_unix_secs`, `last_error`) per unversioned synced API;
  versioned APIs sync per version and report `null` (the
  `service_discovery` precedent).
- An upstream that never answers introspection leaves the seed schema
  serving forever with a permanent `last_error` — visible, not fatal.
- Per-version `schema_sync` comes free (the `graphql` block is already
  wholesale-overridable); each synced version runs its own task against
  its own target.
- Not in v1 (future boxes if wanted): `specifiedByURL`/`isRepeatable` in
  the introspection query, argument/input-field descriptions and
  deprecations in the emitted SDL, a per-API admin trigger, sync jitter,
  surfacing the synced SDL on the admin API.
