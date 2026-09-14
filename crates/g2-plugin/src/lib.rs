//! WASM plugin host for g2way (ADR-0005): compiles guest modules from the
//! gateway's plugins directory and runs them as sandboxed pre/post request
//! hooks behind `g2-middleware`'s [`PluginExec`]/[`PluginLoader`] traits.
//!
//! [`PluginExec`]: g2_middleware::PluginExec
//! [`PluginLoader`]: g2_middleware::PluginLoader
//!
//! # Guest ABI (version 1)
//!
//! A plugin is a core WebAssembly module with **no imports** (no WASI — a
//! guest has no filesystem, network, clock, or environment) exporting:
//!
//! | Export | Signature | Meaning |
//! |---|---|---|
//! | `memory` | linear memory | the module's memory |
//! | `g2_abi_version` | `() -> i32` | must return `1`; checked at load time |
//! | `g2_alloc` | `(len: i32) -> ptr: i32` | reserve `len` bytes of guest memory for the host to write into |
//! | `g2_hook` | `(ptr: i32, len: i32) -> i64` | run the hook; returns `(out_ptr << 32) \| out_len` |
//!
//! Per invocation the host serializes a JSON **input** document, writes it
//! at `g2_alloc(len)`, calls `g2_hook(ptr, len)`, and reads the JSON
//! **output** document the packed return value points at. Guests never free
//! anything: every invocation runs in a fresh, short-lived instance whose
//! memory is reclaimed wholesale afterwards (bump allocators are fine).
//!
//! Input shape (`session` is non-null only for authenticated `post` hooks):
//!
//! ```json
//! {
//!   "abi_version": 1,
//!   "hook": "pre",
//!   "api_id": "users", "org_id": "default",
//!   "plugin_config": {"any": "json from the API definition"},
//!   "request": {
//!     "method": "GET", "path": "/users/1", "query": "page=2",
//!     "headers": [["host", "example.com"], ["x-tag", "a"]],
//!     "client_addr": "203.0.113.9:41200"
//!   },
//!   "session": {"alias": "acme-mobile-app"}
//! }
//! ```
//!
//! Output shape — exactly one of:
//!
//! ```json
//! {"action": "continue",
//!  "set_headers": [["x-user", "42"]], "remove_headers": ["x-internal"]}
//! ```
//! ```json
//! {"action": "respond",
//!  "response": {"status": 403,
//!               "headers": [["content-type", "text/plain"]],
//!               "body": "denied"}}
//! ```
//!
//! Malformed output — invalid JSON, bad header names/values, a status
//! outside `100..=599`, an out-of-bounds pointer — fails the request closed
//! (`500`), as do traps, timeouts and memory-cap hits.
//!
//! # Sandbox limits
//!
//! Execution is bounded by a wall-clock deadline (wasmtime epoch
//! interruption, driven by one process-wide 5 ms ticker thread) and a
//! linear-memory cap; both are per-plugin configuration
//! ([`g2_core::PluginRef`]) with defaults from [`g2_core::plugins`].

mod abi;
mod exec;
mod host;

pub use host::PluginHost;

/// Milliseconds between engine epoch increments; the granularity of plugin
/// timeouts.
pub(crate) const EPOCH_TICK_MS: u64 = 5;

/// The ABI version this host speaks (`g2_abi_version` must return it).
pub const ABI_VERSION: i32 = 1;
