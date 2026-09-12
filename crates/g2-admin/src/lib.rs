//! Admin/control-plane API for g2way.
//!
//! This crate will hold the axum-based admin API (bound on a separate port,
//! protected by an admin secret): CRUD for API keys, API definitions, and
//! policies, plus `/g2/reload` and the node-status endpoints a future
//! dashboard will consume.
//!
//! It is intentionally empty in milestone M1; key management lands in
//! milestone M2 and the full control plane in M4. See `ROADMAP.md` at the
//! workspace root.
