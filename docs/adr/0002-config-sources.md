# ADR-0002: Two configuration sources (files + storage)

Date: 2026-08-30 · Status: accepted

## Context

Through M3 the gateway's API definitions come only from files (`--apps-dir`),
which cannot serve a control plane: admin CRUD and hot reload (M4) need
definitions every pod can see change at runtime. ADR-0001 already fixed Redis
as the shared state backend. What remains to decide is how a storage-backed
definition source coexists with the file loader.

## Decisions

1. **Storage is a second source, not a replacement.** The file loader stays
   (GitOps-style static config, dev, tests); the storage source is read
   through the same `Storage` trait, so `MemoryStorage` deployments simply
   have an empty storage source unless something writes to it. Gateways
   often make file and DB mode exclusive; we deliberately allow both at once
   because static platform APIs (files) and dynamically provisioned APIs
   (admin API → storage) are both real use cases.

2. **Key schema.** One record per definition, JSON-encoded `ApiDefinition`,
   at `g2:{org_id}:apidef:{api_id}` (helpers in `g2_core::api_definition`).
   Policies, when they land, follow the same pattern under
   `g2:{org_id}:policy:{policy_id}`. Records are enumerated with the new
   `Storage::scan_prefix` operation (Redis `SCAN` + `MATCH`; glob characters
   in the prefix are escaped). No index set to keep in sync; `SCAN` is
   cursor-based and non-blocking, and definition loads happen only at
   startup/reload, never per request.

3. **Merging is conflict-checked, never silent.** The two sources are
   concatenated and the same invariants enforced as within one source:
   duplicate `api_id` or `listen_path` (across or within sources) fails the
   load with an error naming both sources. No precedence rule — silently
   shadowing a file-defined API from the admin API (or vice versa) is a
   debugging trap.

4. **A corrupt stored record fails the load loudly** (same as a malformed
   definition file), rather than being skipped: skipping would silently
   unroute an API. The admin API validates on write, so corrupt records
   indicate real trouble. Each record must also round-trip its own storage
   key (`org_id`/`api_id` must match the key it was found under).

## Consequences

- Definition loading becomes async (storage I/O); the binary loads and
  merges inside the runtime before building the route table.
- Adding `scan_prefix` to the `Storage` trait also unblocks the deferred
  `GET /g2/keys` listing (M4).
- Hot reload (M4) re-runs the same load+merge; a conflict introduced at
  runtime must fail the reload and keep the old route table, which the
  ArcSwap design already supports.
