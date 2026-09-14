//! Listen-path routing: mapping a request path to an API definition and its
//! prebuilt middleware chain.

use std::collections::HashMap;
use std::sync::Arc;

use g2_core::{ApiDefinition, Error};
use g2_middleware::SharedJwksFetch;
use g2_middleware::{
    AnalyticsHandle, AnalyticsLayer, AuthLayer, BodyTransformLayer, CacheLayer, ChainBuilder,
    ChainService, CorsLayer, EndpointLimits, GraphQlLayer, HeaderTransformLayer, HookKind,
    HttpMetrics, IpFilterLayer, MetricsLayer, MockResponseLayer, PathPolicyLayer, PluginLayer,
    RateLimitLayer, RequestContext, RequestSizeLimitLayer, SharedPluginLoader, SpikeGuard,
    StatsLayer, StatsRegistry, TraceLayer, VersionDispatch,
};
use g2_storage::SharedStorage;

use crate::forward::{Forward, Forwarder, HttpJwksFetch, UpstreamTarget};

/// Process-wide resources a route(-table) build draws on. All of them
/// outlive any single table: connection pools, storage, guards, counters,
/// instruments and the plugin engine survive hot reloads.
///
/// Optional fields default to `None` via [`RouteResources::new`]; call
/// sites needing more use struct-update syntax on top of it.
#[derive(Clone, Copy)]
pub struct RouteResources<'a> {
    /// Shared upstream client (connection pools, TLS config).
    pub forwarder: &'a Forwarder,
    /// Session/config storage used by auth, rate limiting and caching.
    pub storage: &'a SharedStorage,
    /// Pod-local spike guard fronting the distributed rate limiter.
    pub spike_guard: Option<&'a Arc<SpikeGuard>>,
    /// Per-API request counter registry (survives reloads).
    pub stats: Option<&'a Arc<StatsRegistry>>,
    /// Process-wide OpenTelemetry instruments.
    pub metrics: Option<&'a Arc<HttpMetrics>>,
    /// Handle feeding the process-wide analytics worker.
    pub analytics: Option<&'a AnalyticsHandle>,
    /// Loader turning `plugins` config into runnable WASM hooks; `None`
    /// when the gateway has no plugins directory (definitions declaring
    /// plugins then fail the build).
    pub plugin_loader: Option<&'a SharedPluginLoader>,
}

impl<'a> RouteResources<'a> {
    /// Resources with every optional facility disabled — the minimal build
    /// (and what most tests want).
    #[must_use]
    pub fn new(forwarder: &'a Forwarder, storage: &'a SharedStorage) -> Self {
        Self {
            forwarder,
            storage,
            spike_guard: None,
            stats: None,
            metrics: None,
            analytics: None,
            plugin_loader: None,
        }
    }
}

/// Sets the per-version (inner) layers on `builder` from `def` — the one
/// place the inner half of a chain is configured, shared by the unversioned
/// [`ChainBuilder::build`] path and each version of a versioned API.
///
/// `scope` namespaces the response cache and the endpoint rate-limit
/// counters: the API id for an unversioned API, `{api_id}:{version}` per
/// version of a versioned one — versions can differ in upstream, transforms
/// and limits, so they must never share cached responses or counters.
fn inner_layers(
    builder: ChainBuilder,
    def: &ApiDefinition,
    res: &RouteResources<'_>,
    jwks_fetch: &SharedJwksFetch,
    scope: &str,
) -> Result<ChainBuilder, Error> {
    let storage = res.storage;
    let auth = AuthLayer::from_config(
        &def.auth,
        Arc::clone(storage),
        &def.api_id,
        &def.org_id,
        Some(Arc::clone(jwks_fetch)),
    )?;
    let endpoint_limits =
        EndpointLimits::from_config(&def.endpoint_rate_limits, &def.api_id, &def.org_id, scope)?;
    // Every credentialed API gets the limiter (it is a no-op for sessions
    // without rate/quota); a keyless API gets it only when it declares
    // endpoint limits, which need no session.
    let rate_limit = if auth.is_some() || endpoint_limits.is_some() {
        Some(RateLimitLayer::new(
            &def.api_id,
            Arc::clone(storage),
            res.spike_guard.map(Arc::clone),
            endpoint_limits,
        ))
    } else {
        None
    };
    let transform_headers = def
        .transform_headers
        .as_ref()
        .map(|t| HeaderTransformLayer::from_config(t, &def.api_id))
        .transpose()?;
    let transform_body = def
        .transform_body
        .as_ref()
        .map(|t| BodyTransformLayer::from_config(t, def.max_request_body_bytes, &def.api_id))
        .transpose()?
        .flatten();
    let path_policy = PathPolicyLayer::from_config(
        &def.allow_paths,
        &def.block_paths,
        &def.ignore_auth_paths,
        &def.api_id,
    )?;
    let mock = MockResponseLayer::from_config(&def.mock_responses, &def.api_id)?;
    let size_limit = def.max_request_body_bytes.map(RequestSizeLimitLayer::new);
    let graphql = def
        .graphql
        .as_ref()
        .map(|g| GraphQlLayer::from_config(g, def))
        .transpose()?
        .flatten();
    let cache = def
        .cache
        .as_ref()
        .map(|c| CacheLayer::new(c, scope, &def.org_id, Arc::clone(storage)));
    let (plugins_pre, plugins_post) = match &def.plugins {
        Some(plugins) => (
            PluginLayer::from_config(HookKind::Pre, &plugins.pre, res.plugin_loader, &def.api_id)?,
            PluginLayer::from_config(
                HookKind::Post,
                &plugins.post,
                res.plugin_loader,
                &def.api_id,
            )?,
        ),
        None => (None, None),
    };
    Ok(builder
        .path_policy(path_policy)
        .size_limit(size_limit)
        .plugins_pre(plugins_pre)
        .auth(auth)
        .rate_limit(rate_limit)
        .plugins_post(plugins_post)
        .graphql(graphql)
        .transform_headers(transform_headers)
        .transform_body(transform_body)
        .mock(mock)
        .cache(cache))
}

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
    fn build(def: ApiDefinition, res: &RouteResources<'_>) -> Result<Self, Error> {
        let forwarder = res.forwarder;
        let target = Arc::new(UpstreamTarget::build(&def)?);
        // Shared by every version's auth layer; JWKS documents ride the same
        // pooled client as proxied traffic and health probes.
        let jwks_fetch: SharedJwksFetch = Arc::new(HttpJwksFetch::new(forwarder));
        let ctx = RequestContext::new(def.api_id.clone(), def.org_id.clone());
        let ip_filter = IpFilterLayer::from_config(&def.allow_ips, &def.block_ips, &def.api_id)?;
        let cors = def
            .cors
            .as_ref()
            .map(|c| CorsLayer::from_config(c, &def.api_id))
            .transpose()?;
        // Span names follow the OTel server-span convention (the route, not
        // the full path): the listen path, `/` for a catch-all route.
        let span_name = if target.listen_prefix.is_empty() {
            "/"
        } else {
            target.listen_prefix.as_str()
        };
        let outer = ChainBuilder::new(ctx.clone())
            .trace(Some(TraceLayer::new(ctx.clone(), span_name)))
            .metrics(
                res.metrics
                    .map(|m| MetricsLayer::new(Arc::clone(m), &ctx, span_name)),
            )
            .stats(res.stats.map(|r| StatsLayer::new(r.for_api(&def.api_id))))
            .analytics(
                res.analytics
                    .map(|h| AnalyticsLayer::new(h.clone(), ctx.clone())),
            )
            .ip_filter(ip_filter)
            .cors(cors);
        let chain = match &def.versioning {
            None => {
                if let Some(health) = &def.health_check {
                    crate::health::spawn_checker(forwarder, &target, health);
                }
                if let Some(sd) = &def.service_discovery {
                    crate::discovery::spawn_refresher(forwarder, &target, sd);
                }
                inner_layers(outer, &def, res, &jwks_fetch, &def.api_id)?
                    .build(Forward::new(forwarder, Arc::clone(&target)))
            }
            // A versioned API gets one inner chain per version — each built
            // from the version's effective definition, with its own upstream
            // target — behind a dispatcher wrapped in the shared outer stack.
            Some(versioning) => {
                let mut chains = HashMap::with_capacity(versioning.versions.len());
                for name in versioning.versions.keys() {
                    let vdef = versioning
                        .apply(&def, name)
                        .expect("apply() succeeds for every key of the versions map");
                    let vtarget = Arc::new(UpstreamTarget::build(&vdef)?);
                    if let Some(health) = &vdef.health_check {
                        crate::health::spawn_checker(forwarder, &vtarget, health);
                    }
                    if let Some(sd) = &vdef.service_discovery {
                        crate::discovery::spawn_refresher(forwarder, &vtarget, sd);
                    }
                    let scope = format!("{}:{name}", vdef.api_id);
                    let inner = inner_layers(
                        ChainBuilder::new(ctx.clone()),
                        &vdef,
                        res,
                        &jwks_fetch,
                        &scope,
                    )?
                    .build_inner(Forward::new(forwarder, vtarget));
                    chains.insert(name.clone(), inner);
                }
                outer.build_outer(VersionDispatch::from_config(
                    versioning,
                    chains,
                    &def.api_id,
                )?)
            }
        };
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
    /// the shared client in `res` — see [`RouteResources`] for everything a
    /// build draws on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] if any definition (active or
    /// not) fails validation or a referenced plugin fails to load — a broken
    /// definition should fail loudly at load time, not silently at request
    /// time.
    pub fn build(defs: Vec<ApiDefinition>, res: &RouteResources<'_>) -> Result<Self, Error> {
        let mut routes = Vec::with_capacity(defs.len());
        for def in defs {
            let active = def.active;
            let route = Route::build(def, res)?;
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
        RouteTable::build(defs, &RouteResources::new(&Forwarder::new(), &storage))
    }

    #[tokio::test]
    async fn jwks_route_refreshes_periodically_and_stops_after_drop() {
        use std::convert::Infallible;
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        // A JWKS endpoint counting how often it is fetched.
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let counted = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let counted = Arc::clone(&counted);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |_req| {
                        counted.fetch_add(1, Ordering::Relaxed);
                        async move {
                            Ok::<_, Infallible>(http::Response::new(http_body_util::Full::new(
                                bytes::Bytes::from_static(b"{\"keys\":[]}"),
                            )))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"jwks","name":"jwks","listen_path":"/jwks/",
                "target_url":"http://unused.internal",
                "auth":{{"mode":"jwt","signing_method":"rs256",
                         "jwks_url":"http://{addr}/jwks.json",
                         "jwks_refresh_secs":1}}}}"#
        ))
        .expect("def");
        let storage: SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
        let table = RouteTable::build(vec![def], &RouteResources::new(&Forwarder::new(), &storage))
            .expect("build");

        // Eager fetch plus at least one 1s periodic tick.
        tokio::time::timeout(Duration::from_secs(10), async {
            while hits.load(Ordering::Relaxed) < 2 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("background refresh keeps fetching");

        // Dropping the table (a config reload) reaps the refresher.
        drop(table);
        tokio::time::sleep(Duration::from_millis(200)).await; // drain in-flight
        let settled = hits.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(
            hits.load(Ordering::Relaxed),
            settled,
            "no fetches after the owning table is dropped"
        );
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
    fn keyless_definition_with_endpoint_limits_builds_a_route() {
        // Keyless APIs normally get no RateLimitLayer; endpoint limits must
        // still build one (behavior is covered by the e2e suite).
        let mut d = def("erl", "/erl/", "http://u.internal");
        d.endpoint_rate_limits = vec![g2_core::EndpointRateLimit {
            pattern: "^/erl/limited".into(),
            methods: vec![],
            rate: g2_core::session::RateLimit {
                requests: 1,
                per_seconds: 60,
            },
        }];
        let table = table(vec![d]).expect("build");
        assert!(table.match_path("/erl/limited").is_some());
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
    fn versioned_definition_builds_a_route() {
        let mut d = def("versioned", "/v/", "http://v1.internal");
        d.versioning = Some(
            serde_json::from_str(
                r#"{
                    "default_version": "v1",
                    "versions": {"v1": {}, "v2": {"target_url": "http://v2.internal"}}
                }"#,
            )
            .expect("versioning JSON"),
        );
        let built = table(vec![d]).expect("build");
        let route = built.match_path("/v/x").expect("route");
        // The route's own target stays the base definition's.
        assert_eq!(
            route.target.target_set().addrs[0].authority.as_str(),
            "v1.internal"
        );

        // A broken override fails the build like any invalid definition.
        let mut d = def("versioned", "/v/", "http://v1.internal");
        d.versioning = Some(
            serde_json::from_str(r#"{"versions": {"v2": {"target_url": "nope"}}}"#)
                .expect("versioning JSON"),
        );
        assert!(table(vec![d]).is_err());
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
        let set = route.target.target_set();
        let addr = &set.addrs[0];
        assert_eq!(addr.scheme.as_str(), "https");
        assert_eq!(addr.authority.as_str(), "api.internal:8443");
        assert_eq!(addr.base_path, "/base");
    }

    #[test]
    fn empty_table_matches_nothing() {
        let table = table(vec![]).expect("build");
        assert!(table.match_path("/anything").is_none());
    }
}
