//! The g2way proxy engine.
//!
//! Requests flow through three stages, all designed to keep the hot path
//! lock-free:
//!
//! 1. **Routing** — [`RouteTable`] matches the request path against the
//!    loaded API definitions (longest listen-path prefix wins). The table is
//!    immutable; [`Gateway`] holds it in an `ArcSwap` so a config reload is a
//!    single atomic pointer swap and in-flight requests keep the table they
//!    started with.
//! 2. **Rewriting** — the private `rewrite` module strips the listen path,
//!    joins the upstream base path, removes hop-by-hop headers, and adds
//!    `X-Forwarded-*` headers.
//! 3. **Forwarding** — a shared pooled hyper client streams the request to
//!    the upstream and the response back, enforcing the per-API upstream
//!    timeout.
//!
//! [`Gateway::handle`] is the single entry point the binary calls per request.

pub mod gateway;
mod rewrite;
pub mod router;

pub use gateway::{Gateway, ProxyBody};
pub use router::{Route, RouteTable};
