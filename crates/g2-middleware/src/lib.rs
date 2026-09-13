//! Tower middleware layers for g2way.
//!
//! Every API gets its own middleware chain — authentication, rate limiting,
//! quotas, transforms (arriving through milestone M2 and beyond) — composed
//! **once at config-load time** into a [`ChainService`] stored on the route.
//! Per request the gateway clones that boxed service (cheap: one small
//! allocation) and drives it with `tower::ServiceExt::oneshot`; no locks are
//! taken and no composition happens on the hot path (ADR-0001).
//!
//! The chain's error type is [`Infallible`](std::convert::Infallible): every
//! failure inside the chain is mapped to an HTTP [`Response`](http::Response)
//! (e.g. `401`, `429`, `502`), so the gateway's "never returns an error"
//! contract holds end to end.
//!
//! Layers communicate through request extensions: [`SetContextLayer`] stamps
//! the per-API [`RequestContext`] outermost, [`AuthLayer`] adds the resolved
//! [`SessionContext`], and downstream layers (like [`ApiIdHeaderLayer`])
//! read them back.

pub mod api_id_header;
pub mod auth;
pub mod body;
pub mod chain;
pub mod context;
pub mod metrics;
pub mod rate_limit;
pub mod response;
pub mod set_context;
pub mod spike;
pub mod stats;
pub mod trace;

pub use api_id_header::{ApiIdHeader, ApiIdHeaderLayer, API_ID_HEADER};
pub use auth::{Auth, AuthLayer};
pub use body::ProxyBody;
pub use chain::ChainBuilder;
pub use context::{ClientAddr, RequestContext, SessionContext};
pub use metrics::{HttpMetrics, MetricsLayer};
pub use rate_limit::{RateLimit, RateLimitLayer};
pub use set_context::{SetContext, SetContextLayer};
pub use spike::SpikeGuard;
pub use stats::{ApiStats, ApiStatsSnapshot, StatsLayer, StatsRegistry};
pub use trace::{Trace, TraceLayer};

/// Boxed error type used for proxied body streams.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A fully composed per-API middleware chain, boxed for storage on a route.
///
/// Built by [`ChainBuilder::build`] at route-build time. `Clone` is required
/// because tower's `Service::call` needs `&mut self` while routes live behind
/// an `Arc`: the gateway clones the chain per request and drives the clone.
pub type ChainService = tower::util::BoxCloneSyncService<
    http::Request<ProxyBody>,
    http::Response<ProxyBody>,
    std::convert::Infallible,
>;
