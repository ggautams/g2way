//! Tower middleware layers for g2way.
//!
//! This crate will hold the per-API middleware chain — authentication, rate
//! limiting, quotas, header/URL transforms, CORS, IP filtering — composed at
//! config-load time into each route.
//!
//! It is intentionally empty in milestone M1; the first layers (auth token,
//! JWT) land in milestone M2. See `ROADMAP.md` at the workspace root.
