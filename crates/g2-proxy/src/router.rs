//! Listen-path routing: mapping a request path to an API definition and its
//! prebuilt middleware chain.

use std::sync::Arc;

use g2_core::{ApiDefinition, Error};
use g2_middleware::{
    AnalyticsHandle, AnalyticsLayer, AuthLayer, ChainBuilder, ChainService, CorsLayer,
    HeaderTransformLayer, HttpMetrics, IpFilterLayer, MetricsLayer, MockResponseLayer,
    PathPolicyLayer, RateLimitLayer, RequestContext, RequestSizeLimitLayer, SpikeGuard, StatsLayer,
    StatsRegistry, TraceLayer,
};
use g2_storage::SharedStorage;

use crate::forward::{Forward, Forwarder, UpstreamTarget};

/// One routable API: a validated [`ApiDefinition`] plus everything
/// precomputed at build time — upstream target parts and the composed
/// middleware chain — so the per-request hot path does no parsing and no
/// composition (ADR-0001).
#[derive(Clone)]
pub struct Route {
    /// The API definition this route was built from.
    pub def: ApiDefinition,
    /// `listen_path` with any trailing `/` removed (`"/users"`; empty for `"/"`).
    pub listen_prefix: String,
    /// Precomputed upstream target parts.
    pub target: Arc<UpstreamTarget>,
    /// The API's middleware chain, ending in the upstream forwarder. Cloned
    /// per request by the gateway.
    pub(crate) chain: ChainService,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("def", &self.def)
            .field("listen_prefix", &self.listen_prefix)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Route {
    fn build(
        def: ApiDefinition,
        forwarder: &Forwarder,
        storage: &SharedStorage,
        spike_guard: Option<&Arc<SpikeGuard>>,
        stats: Option<&Arc<StatsRegistry>>,
        metrics: Option<&Arc<HttpMetrics>>,
        analytics: Option<&AnalyticsHandle>,
    ) -> Result<Self, Error> {
        let target = Arc::new(UpstreamTarget::build(&def)?);
        let ctx = RequestContext::new(def.api_id.clone(), def.org_id.clone());
        let auth =
            AuthLayer::from_config(&def.auth, Arc::clone(storage), &def.api_id, &def.org_id)?;
        // Keyless APIs carry no session, so there are no limits to read;
        // every credentialed API gets the limiter (it is a no-op for
        // sessions without rate/quota).
        let rate_limit = auth.as_ref().map(|_| {
            RateLimitLayer::new(
                &def.api_id,
                Arc::clone(storage),
                spike_guard.map(Arc::clone),
            )
        });
        let transform_headers = def
            .transform_headers
            .as_ref()
            .map(|t| HeaderTransformLayer::from_config(t, &def.api_id))
            .transpose()?;
        let path_policy = PathPolicyLayer::from_config(
            &def.allow_paths,
            &def.block_paths,
            &def.ignore_auth_paths,
            &def.api_id,
        )?;
        let mock = MockResponseLayer::from_config(&def.mock_responses, &def.api_id)?;
        let ip_filter = IpFilterLayer::from_config(&def.allow_ips, &def.block_ips, &def.api_id)?;
        let cors = def
            .cors
            .as_ref()
            .map(|c| CorsLayer::from_config(c, &def.api_id))
            .transpose()?;
        let size_limit = def.max_request_body_bytes.map(RequestSizeLimitLayer::new);
        // Span names follow the OTel server-span convention (the route, not
        // the full path): the listen path, `/` for a catch-all route.
        let span_name = if target.listen_prefix.is_empty() {
            "/"
        } else {
            target.listen_prefix.as_str()
        };
        let chain = ChainBuilder::new(ctx.clone())
            .trace(Some(TraceLayer::new(ctx.clone(), span_name)))
            .metrics(metrics.map(|m| MetricsLayer::new(Arc::clone(m), &ctx, span_name)))
            .stats(stats.map(|r| StatsLayer::new(r.for_api(&def.api_id))))
            .analytics(analytics.map(|h| AnalyticsLayer::new(h.clone(), ctx.clone())))
            .ip_filter(ip_filter)
            .cors(cors)
            .path_policy(path_policy)
            .size_limit(size_limit)
            .auth(auth)
            .rate_limit(rate_limit)
            .transform_headers(transform_headers)
            .mock(mock)
            .build(Forward::new(forwarder, Arc::clone(&target)));
        Ok(Self {
            listen_prefix: target.listen_prefix.clone(),
            def,
            target,
            chain,
        })
    }

    /// Whether `path` falls under this route's listen path.
    ///
    /// `/users` matches `/users` and `/users/42` but not `/users2`. A listen
    /// path of `/` matches every path.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        if self.listen_prefix.is_empty() {
            return true;
        }
        match path.strip_prefix(self.listen_prefix.as_str()) {
            Some(rest) => rest.is_empty() || rest.starts_with('/'),
            None => false,
        }
    }
}

/// An immutable, prebuilt routing table.
///
/// Built once per config (re)load from the full set of API definitions and
/// swapped into the gateway atomically. Matching scans routes ordered by
/// listen-path length, so the most specific (longest) prefix wins.
#[derive(Debug, Default)]
pub struct RouteTable {
    /// Routes sorted by `listen_prefix` length, longest first.
    routes: Vec<Arc<Route>>,
}

impl RouteTable {
    /// Builds a table from definitions, skipping inactive ones. Each route's
    /// middleware chain is composed here, around a forwarding service using
    /// `forwarder`'s shared client; token-auth APIs look sessions up in
    /// `storage`. `spike_guard` is the optional process-wide pod-local
    /// guard shared by every route's rate limiter, `stats` the optional
    /// process-wide counter registry (shared across reloads so counters
    /// survive table swaps), `metrics` the optional process-wide
    /// OpenTelemetry instruments every route records into, and `analytics`
    /// the optional handle feeding the process-wide analytics worker.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] if any definition (active or
    /// not) fails validation — a broken definition should fail loudly at load
    /// time, not silently at request time.
    pub fn build(
        defs: Vec<ApiDefinition>,
        forwarder: &Forwarder,
        storage: &SharedStorage,
        spike_guard: Option<&Arc<SpikeGuard>>,
        stats: Option<&Arc<StatsRegistry>>,
        metrics: Option<&Arc<HttpMetrics>>,
        analytics: Option<&AnalyticsHandle>,
    ) -> Result<Self, Error> {
        let mut routes = Vec::with_capacity(defs.len());
        for def in defs {
            let active = def.active;
            let route = Route::build(
                def,
                forwarder,
                storage,
                spike_guard,
                stats,
                metrics,
                analytics,
            )?;
            if active {
                routes.push(Arc::new(route));
            } else {
                tracing::info!(api_id = %route.def.api_id, "skipping inactive API");
            }
        }
        routes.sort_by(|a, b| {
            b.listen_prefix
                .len()
                .cmp(&a.listen_prefix.len())
                .then_with(|| a.listen_prefix.cmp(&b.listen_prefix))
        });
        Ok(Self { routes })
    }

    /// Finds the route for `path`, preferring the longest listen-path match.
    #[must_use]
    pub fn match_path(&self, path: &str) -> Option<&Arc<Route>> {
        self.routes.iter().find(|r| r.matches(path))
    }

    /// All active routes, most specific first (for status/introspection APIs).
    #[must_use]
    pub fn routes(&self) -> &[Arc<Route>] {
        &self.routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(api_id: &str, listen_path: &str, target_url: &str) -> ApiDefinition {
        serde_json::from_str(&format!(
            r#"{{"api_id":"{api_id}","name":"{api_id}","listen_path":"{listen_path}","target_url":"{target_url}","auth":{{"mode":"keyless"}}}}"#
        ))
        .expect("valid definition")
    }

    fn table(defs: Vec<ApiDefinition>) -> Result<RouteTable, Error> {
        let storage: SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
        RouteTable::build(defs, &Forwarder::new(), &storage, None, None, None, None)
    }

    #[test]
    fn longest_prefix_wins() {
        let table = table(vec![
            def("all", "/", "http://all.internal"),
            def("users", "/users/", "http://users.internal"),
            def("user-admin", "/users/admin/", "http://admin.internal"),
        ])
        .expect("build");

        let hit = |p: &str| table.match_path(p).expect("route").def.api_id.clone();
        assert_eq!(hit("/users/admin/x"), "user-admin");
        assert_eq!(hit("/users/admin"), "user-admin");
        assert_eq!(hit("/users/42"), "users");
        assert_eq!(hit("/other"), "all");
        assert_eq!(hit("/"), "all");
    }

    #[test]
    fn prefix_matches_whole_segments_only() {
        let table = table(vec![def("users", "/users", "http://u.internal")]).expect("build");
        assert!(table.match_path("/users").is_some());
        assert!(table.match_path("/users/").is_some());
        assert!(table.match_path("/users/42").is_some());
        assert!(table.match_path("/users2").is_none());
        assert!(table.match_path("/user").is_none());
    }

    #[test]
    fn trailing_slash_in_listen_path_is_ignored_for_matching() {
        let with = table(vec![def("a", "/svc/", "http://u.internal")]).expect("build");
        let without = table(vec![def("a", "/svc", "http://u.internal")]).expect("build");
        for t in [&with, &without] {
            assert!(t.match_path("/svc").is_some());
            assert!(t.match_path("/svc/x").is_some());
        }
    }

    #[test]
    fn inactive_apis_are_not_routed() {
        let mut d = def("off", "/off/", "http://u.internal");
        d.active = false;
        let table = table(vec![d]).expect("build");
        assert!(table.match_path("/off/x").is_none());
        assert!(table.routes().is_empty());
    }

    #[test]
    fn invalid_definition_fails_the_whole_build() {
        let bad = def("bad", "/ok/", "not-a-url");
        assert!(table(vec![bad]).is_err());
    }

    #[test]
    fn route_precomputes_target_parts() {
        let table = table(vec![def("a", "/a/", "https://api.internal:8443/base/")]).expect("build");
        let route = table.match_path("/a/x").expect("route");
        assert_eq!(route.target.scheme.as_str(), "https");
        assert_eq!(route.target.authority.as_str(), "api.internal:8443");
        assert_eq!(route.target.base_path, "/base");
    }

    #[test]
    fn empty_table_matches_nothing() {
        let table = table(vec![]).expect("build");
        assert!(table.match_path("/anything").is_none());
    }
}
