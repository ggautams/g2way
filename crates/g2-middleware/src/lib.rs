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

pub mod analytics;
pub mod api_id_header;
pub mod auth;
pub mod body;
pub mod cache;
pub mod chain;
pub mod context;
pub mod cors;
pub mod graphql;
pub(crate) mod graphql_federation;
pub mod graphql_sync;
pub(crate) mod graphql_udg;
pub mod graphql_ws;
pub(crate) mod hmac;
pub mod ip_filter;
pub mod jwks;
pub mod metrics;
pub mod mock;
pub mod path_policy;
pub mod plugin;
pub mod rate_limit;
pub mod response;
pub mod set_context;
pub mod size_limit;
pub mod spike;
pub mod stats;
pub mod trace;
pub mod transform_body;
pub mod transform_headers;
pub mod udg_fetch;
pub mod versioning;

pub use analytics::{Analytics, AnalyticsHandle, AnalyticsLayer};
pub use api_id_header::{ApiIdHeader, ApiIdHeaderLayer, API_ID_HEADER};
pub use auth::{Auth, AuthLayer};
pub use body::ProxyBody;
pub use cache::{Cache, CacheLayer, CACHE_STATUS_HEADER};
pub use chain::ChainBuilder;
pub use context::{
    AuthBypass, ClientAddr, ConnectionInfo, RequestContext, SessionContext, UpstreamLatency,
};
pub use cors::{Cors, CorsLayer};
pub use graphql::{GraphQl, GraphQlLayer};
pub use graphql_sync::{
    introspection_to_sdl, GraphQlSyncHandle, SchemaSyncSnapshot, SyncNudge, WeakGraphQlSync,
    INTROSPECTION_QUERY,
};
pub use graphql_ws::GraphQlWsTunnel;
pub use ip_filter::{IpFilter, IpFilterLayer};
pub use jwks::{JwksFetch, JwksFetchFuture, SharedJwksFetch};
pub use metrics::{HttpMetrics, MetricsLayer};
pub use mock::{Mock, MockResponseLayer};
pub use path_policy::{PathPolicy, PathPolicyLayer};
pub use plugin::{
    HookInvocation, HookKind, HookOutcome, Plugin, PluginExec, PluginLayer, PluginLoader,
    SharedPluginExec, SharedPluginLoader,
};
pub use rate_limit::{EndpointLimits, RateLimit, RateLimitLayer};
pub use set_context::{SetContext, SetContextLayer};
pub use size_limit::{
    is_request_too_large, RequestSizeLimit, RequestSizeLimitLayer, RequestTooLarge,
};
pub use spike::SpikeGuard;
pub use stats::{ApiStats, ApiStatsSnapshot, StatsLayer, StatsRegistry};
pub use trace::{Trace, TraceLayer};
pub use transform_body::{BodyTransformLayer, BodyTransformer};
pub use transform_headers::{HeaderTransformLayer, HeaderTransformer};
pub use udg_fetch::{SharedUdgFetch, UdgFetch, UdgFetchFuture, UdgRequest, UdgResponse};
pub use versioning::VersionDispatch;

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
