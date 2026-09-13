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
//! 2. **Middleware chain** — each route carries a per-API tower stack from
//!    `g2-middleware`, composed once at table-build time (never per request);
//!    the gateway clones the boxed chain and drives it with `oneshot`.
//! 3. **Forwarding** — the chain's innermost service (the `forward` module)
//!    maps the path (regex URL rewrites first, else listen-path strip plus
//!    upstream base-path join), applies any method transform, removes
//!    hop-by-hop headers, adds `X-Forwarded-*`, and streams the request to
//!    one of the upstream's addresses (round-robin across a `target_list`
//!    when configured, skipping addresses evicted by the `health` module's
//!    active probes) through a shared pooled hyper client ([`Forwarder`],
//!    speaking TLS to `https://` targets via rustls), enforcing the per-API
//!    upstream timeout.
//!
//! [`Gateway::handle`] is the single entry point the binary calls per request.

pub mod forward;
pub mod gateway;
mod health;
mod response;
mod rewrite;
pub mod router;

pub use forward::{Forwarder, UpstreamAddr, UpstreamTarget};
pub use gateway::{Gateway, ProxyBody};
pub use router::{Route, RouteTable};
