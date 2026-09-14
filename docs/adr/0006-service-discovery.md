# ADR-0006: Upstream service discovery

Date: 2026-09-01 · Status: accepted

## Context

A serious gateway needs service discovery: upstream addresses resolved at
runtime from an external catalog (Consul, etcd, Eureka, or any HTTP+JSON
endpoint) instead of a static `target_url`/`target_list`. That collides with
ADR-0001 §4: the route table is immutable and replaced wholesale on reload,
and `UpstreamTarget` — including its address list and the health checker's
per-address flags — has been built once per table. Discovery means the
address list changes *between* reloads.

## Decisions

1. **v1 speaks HTTP+JSON polling only.** Each configured API polls a
   `service_discovery.endpoint` on an interval and extracts addresses from
   the JSON response via dotted data paths (`data_path`, `port_data_path`,
   `parent_data_path`) — one mechanism covers the REST catalogs of
   Consul/etcd/Eureka. Considered and
   deliberately excluded: DNS SRV lookups (a second resolver stack for a
   niche win) and the Kubernetes Endpoints API (a k8s client dependency and
   RBAC coupling; k8s users already get L4 balancing from Services).
   Deliberately absent: `use_nested_query` (JSON-inside-a-JSON-string double
   parse) and `use_target_list` (g2way always uses every discovered entry;
   a single string is a one-element list). The response body cap is a
   constant 1 MiB, like JWKS fetches.

2. **Scoped amendment to ADR-0001 §4: one designated swappable leaf.**
   Routing *structure* stays immutable-swap-on-reload, but each route's
   address list moves behind `ArcSwap<TargetSet>` inside its
   `UpstreamTarget`. A discovery change swaps that one leaf wholesale and
   touches nothing else — it must never rebuild the route table (that would
   re-run every layer's config work on every poll). The hot path stays
   lock-free and allocation-free: one extra wait-free `ArcSwap` load per
   forwarding attempt, the same blessed pattern the route table itself uses.

3. **Health flags live inside the `TargetSet`.** The flags-index-matches-
   address invariant becomes structural: a swapped-in set carries its own
   fresh all-healthy `HealthState` (when the API health-checks), and the
   checker task re-derives probe URIs and streaks whenever it observes a new
   set pointer. Considered instead: forbidding `health_check` +
   `service_discovery` on one API — rejected because the invasive part (the
   swappable list) was needed anyway, and the combination is genuinely
   useful (the catalog says who exists; probes say who answers).

4. **Stale-on-error, never empty.** A failed poll — transport error,
   non-2xx, oversized or unparseable body, extraction error, invalid entry,
   or an *empty* result — keeps the previous set and warns (the JWKS
   refresher's rule: stale targets beat empty targets). `target_url` stays
   required and seeds the set with `target_list`, so a target always has
   somewhere to forward, even before the first successful poll. One
   deliberate asymmetry with JWKS: an empty *successful* JWKS answer is
   authoritative (revocation), an empty discovery answer is not (a gateway
   with zero upstreams serves nobody).

5. **Pod-local polling, Weak-based lifecycle.** Each pod polls the endpoint
   itself (no cross-pod coordination, like health probing and the
   round-robin cursor); N pods mean N pollers per API — poll jitter is a
   noted future knob if that ever hurts a catalog. The refresher task holds
   only a `Weak` to its target and self-exits after a reload drops the old
   table, exactly like the health checker and JWKS refresher. Discovery
   endpoints are fetched over the shared HTTP/1.1 pool regardless of the
   API's `upstream_http2`.

## Consequences

- `UpstreamTarget` is now "structurally immutable": all config-derived
  fields still never change, but the target set read through
  `target_set()` can differ between two loads. Code must not cache
  addresses across requests, and guards must be held only briefly.
- The circuit breaker is unaffected: it is per-route and address-blind.
- Per-version `service_discovery` overrides work like `health_check`
  (wholesale replace; each version polls its own endpoint).
- `/g2/node` reports `live_targets` (the addresses actually in rotation)
  and a `service_discovery` status block per API.
- Not in v1 (future boxes if wanted): DNS SRV / k8s Endpoints sources,
  poll jitter, per-API CA for the discovery endpoint, weighting from
  catalog metadata.
