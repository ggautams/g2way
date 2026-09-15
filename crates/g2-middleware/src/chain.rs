//! [`ChainBuilder`]: composes one API's middleware chain at route-build time.

use std::convert::Infallible;

use http::{Request, Response};
use tower::util::BoxCloneSyncService;
use tower::{Service, ServiceBuilder};

use crate::analytics::AnalyticsLayer;
use crate::api_id_header::ApiIdHeaderLayer;
use crate::auth::AuthLayer;
use crate::cache::CacheLayer;
use crate::context::RequestContext;
use crate::cors::CorsLayer;
use crate::graphql::GraphQlLayer;
use crate::ip_filter::IpFilterLayer;
use crate::metrics::MetricsLayer;
use crate::mock::MockResponseLayer;
use crate::path_policy::PathPolicyLayer;
use crate::plugin::PluginLayer;
use crate::rate_limit::RateLimitLayer;
use crate::set_context::SetContextLayer;
use crate::size_limit::RequestSizeLimitLayer;
use crate::stats::StatsLayer;
use crate::trace::TraceLayer;
use crate::transform_body::BodyTransformLayer;
use crate::transform_headers::HeaderTransformLayer;
use crate::{ChainService, ProxyBody};

/// Builds the middleware chain for one API.
///
/// Called once per route when a route table is (re)built, never on the hot
/// path. The resulting [`ChainService`] wraps the innermost forwarding
/// service with, outermost first:
///
/// 1. [`TraceLayer`] — the per-request tracing span (outermost so every
///    layer below runs inside it and can record span fields; absent when
///    tracing is disabled).
/// 2. [`MetricsLayer`] — the per-request duration histogram sample (absent
///    when metrics are disabled).
/// 3. [`StatsLayer`] — per-API request counters (above auth so rejections
///    count too; absent when stats are disabled).
/// 4. [`AnalyticsLayer`] — per-request analytics records (above auth for
///    the same reason; absent when no analytics sink is configured).
/// 5. [`SetContextLayer`] — stamps the [`RequestContext`] extension.
/// 6. [`IpFilterLayer`] — client-IP allow/deny lists (absent when
///    unconfigured). Outermost policy layer: a blocked client gets nothing
///    — no CORS headers, no path evaluation, no credential work.
/// 7. [`CorsLayer`] — CORS preflight answers and response decoration
///    (absent when unconfigured). Above auth so preflights need no
///    credentials and 401/403/429 rejections still carry CORS headers.
/// 8. [`PathPolicyLayer`] — allow/block/ignore path lists (absent when
///    unconfigured). Above auth so blocked paths are rejected before any
///    credential work and ignored paths can tell auth to stand down.
/// 9. [`RequestSizeLimitLayer`] — request body size limit (absent when
///    unconfigured). Above auth so oversized requests are rejected before
///    any credential work.
/// 10. [`PluginLayer`] (pre) — WASM pre hooks (absent when unconfigured).
///     Directly above auth so hooks can inject or transform credentials
///     before they are checked, and below the path/size policies so
///     statically-rejected requests buy no plugin CPU. Below CORS, so a
///     hook's short-circuit response still gets CORS decoration.
/// 11. [`AuthLayer`] — token auth (absent for keyless APIs).
/// 12. [`RateLimitLayer`] — endpoint rate limits plus session rate/quota
///     enforcement (absent only for keyless APIs without endpoint rate
///     limits: session limits need a session, endpoint limits do not).
/// 13. [`PluginLayer`] (post) — WASM post hooks (absent when unconfigured).
///     Below auth/rate-limit so hooks see the authenticated session and
///     401/403/429 rejections never invoke them; above GraphQL and the
///     header transforms so session-based hook decisions run before any
///     payload work and hook short-circuits stay untransformed like every
///     other gateway rejection.
/// 14. [`GraphQlLayer`] — GraphQL protections, playground, and persisted
///     queries (absent when unconfigured). Below auth/rate-limit so the
///     per-key grants are resolved, the playground stays credentialed, and
///     rejected requests buy no parse work; above the header transforms so
///     GraphQL rejections stay untransformed and the persisted-query
///     rewrite happens before request transforms see the upstream-bound
///     request. In `udg` execution mode this layer answers every GraphQL
///     request itself (ADR-0010) — the slots below it never run.
/// 15. [`HeaderTransformLayer`] — per-API header add/remove on requests and
///     responses (absent when unconfigured). Below auth/rate-limit so
///     gateway rejections are not transformed; above [`ApiIdHeaderLayer`] so
///     a transform can never spoof the anti-spoof api-id header.
/// 16. [`BodyTransformLayer`] — per-API minijinja body transforms on
///     matching request and response bodies (absent when unconfigured).
///     Below auth/rate-limit so gateway rejections keep their bodies;
///     directly below the header transforms so the two transform kinds
///     travel together (on requests a body rule's `content_type` wins over
///     a header-transform `add`; on responses a header-transform `add`
///     wins), and above mocks/cache like them.
/// 17. [`MockResponseLayer`] — gateway-answered mock responses (absent when
///     unconfigured). Below auth/rate-limit (mocks on a protected API stay
///     protected) and below the header transforms, so mock responses get
///     the API's response transforms like any upstream response.
/// 18. [`CacheLayer`] — shared response caching for safe requests (absent
///     when unconfigured). Below auth/rate-limit so cache hits still
///     require credentials and consume rate, below the header transforms so
///     the stored copy is the raw upstream response (transforms re-apply
///     live on every hit), and below mocks so mock responses — already
///     gateway-local — are never cached.
/// 19. [`ApiIdHeaderLayer`] — sets `x-g2-api-id` on the upstream-bound
///     request. Innermost, so neither transforms nor plugins can spoof it.
///
/// [`Self::build`] composes the full stack for an unversioned API. A
/// versioned API splits the stack around its version dispatcher instead:
/// [`Self::build_outer`] composes the shared, version-independent layers
/// (items 1–7) around the dispatcher, and [`Self::build_inner`] composes
/// the per-version layers (items 8–19) around each version's forwarder.
/// The three methods must keep the ordering above consistent.
#[derive(Debug, Clone)]
pub struct ChainBuilder {
    ctx: RequestContext,
    auth: Option<AuthLayer>,
    rate_limit: Option<RateLimitLayer>,
    stats: Option<StatsLayer>,
    trace: Option<TraceLayer>,
    metrics: Option<MetricsLayer>,
    analytics: Option<AnalyticsLayer>,
    ip_filter: Option<IpFilterLayer>,
    cors: Option<CorsLayer>,
    path_policy: Option<PathPolicyLayer>,
    size_limit: Option<RequestSizeLimitLayer>,
    plugins_pre: Option<PluginLayer>,
    plugins_post: Option<PluginLayer>,
    graphql: Option<GraphQlLayer>,
    transform_headers: Option<HeaderTransformLayer>,
    transform_body: Option<BodyTransformLayer>,
    mock: Option<MockResponseLayer>,
    cache: Option<CacheLayer>,
}

impl ChainBuilder {
    /// Starts a chain for the API identified by `ctx`.
    #[must_use]
    pub fn new(ctx: RequestContext) -> Self {
        Self {
            ctx,
            auth: None,
            rate_limit: None,
            stats: None,
            trace: None,
            metrics: None,
            analytics: None,
            ip_filter: None,
            cors: None,
            path_policy: None,
            size_limit: None,
            plugins_pre: None,
            plugins_post: None,
            graphql: None,
            transform_headers: None,
            transform_body: None,
            mock: None,
            cache: None,
        }
    }

    /// Adds the per-request tracing span (`None` is a no-op).
    #[must_use]
    pub fn trace(mut self, trace: Option<TraceLayer>) -> Self {
        self.trace = trace;
        self
    }

    /// Adds per-request duration metrics (`None` is a no-op).
    #[must_use]
    pub fn metrics(mut self, metrics: Option<MetricsLayer>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Adds per-request analytics records (`None` is a no-op).
    #[must_use]
    pub fn analytics(mut self, analytics: Option<AnalyticsLayer>) -> Self {
        self.analytics = analytics;
        self
    }

    /// Adds per-API request counting (`None` is a no-op).
    #[must_use]
    pub fn stats(mut self, stats: Option<StatsLayer>) -> Self {
        self.stats = stats;
        self
    }

    /// Adds token authentication (`None` — from a keyless config — is a
    /// no-op, keeping the call site branch-free).
    #[must_use]
    pub fn auth(mut self, auth: Option<AuthLayer>) -> Self {
        self.auth = auth;
        self
    }

    /// Adds rate/quota enforcement (`None` is a no-op).
    #[must_use]
    pub fn rate_limit(mut self, rate_limit: Option<RateLimitLayer>) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// Adds client-IP allow/deny enforcement (`None` is a no-op).
    #[must_use]
    pub fn ip_filter(mut self, ip_filter: Option<IpFilterLayer>) -> Self {
        self.ip_filter = ip_filter;
        self
    }

    /// Adds CORS handling (`None` is a no-op).
    #[must_use]
    pub fn cors(mut self, cors: Option<CorsLayer>) -> Self {
        self.cors = cors;
        self
    }

    /// Adds allow/block/ignore path-list enforcement (`None` is a no-op).
    #[must_use]
    pub fn path_policy(mut self, path_policy: Option<PathPolicyLayer>) -> Self {
        self.path_policy = path_policy;
        self
    }

    /// Adds request body size enforcement (`None` is a no-op).
    #[must_use]
    pub fn size_limit(mut self, size_limit: Option<RequestSizeLimitLayer>) -> Self {
        self.size_limit = size_limit;
        self
    }

    /// Adds WASM pre hooks, run directly above auth (`None` is a no-op).
    #[must_use]
    pub fn plugins_pre(mut self, plugins_pre: Option<PluginLayer>) -> Self {
        self.plugins_pre = plugins_pre;
        self
    }

    /// Adds WASM post hooks, run directly below rate limiting (`None` is a
    /// no-op).
    #[must_use]
    pub fn plugins_post(mut self, plugins_post: Option<PluginLayer>) -> Self {
        self.plugins_post = plugins_post;
        self
    }

    /// Adds GraphQL protections, playground, and persisted queries (`None`
    /// is a no-op).
    #[must_use]
    pub fn graphql(mut self, graphql: Option<GraphQlLayer>) -> Self {
        self.graphql = graphql;
        self
    }

    /// Adds header add/remove transforms (`None` is a no-op).
    #[must_use]
    pub fn transform_headers(mut self, transform_headers: Option<HeaderTransformLayer>) -> Self {
        self.transform_headers = transform_headers;
        self
    }

    /// Adds minijinja body transforms (`None` is a no-op).
    #[must_use]
    pub fn transform_body(mut self, transform_body: Option<BodyTransformLayer>) -> Self {
        self.transform_body = transform_body;
        self
    }

    /// Adds gateway-answered mock responses (`None` is a no-op).
    #[must_use]
    pub fn mock(mut self, mock: Option<MockResponseLayer>) -> Self {
        self.mock = mock;
        self
    }

    /// Adds shared response caching (`None` is a no-op).
    #[must_use]
    pub fn cache(mut self, cache: Option<CacheLayer>) -> Self {
        self.cache = cache;
        self
    }

    /// Wraps `forward` — the innermost service that actually proxies to the
    /// upstream — with this chain's layers, returning the boxed, cloneable
    /// service stored on a route.
    pub fn build<S>(self, forward: S) -> ChainService
    where
        S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let svc = ServiceBuilder::new()
            .option_layer(self.trace)
            .option_layer(self.metrics)
            .option_layer(self.stats)
            .option_layer(self.analytics)
            .layer(SetContextLayer::new(self.ctx))
            .option_layer(self.ip_filter)
            .option_layer(self.cors)
            .option_layer(self.path_policy)
            .option_layer(self.size_limit)
            .option_layer(self.plugins_pre)
            .option_layer(self.auth)
            .option_layer(self.rate_limit)
            .option_layer(self.plugins_post)
            .option_layer(self.graphql)
            .option_layer(self.transform_headers)
            .option_layer(self.transform_body)
            .option_layer(self.mock)
            .option_layer(self.cache)
            .layer(ApiIdHeaderLayer::new())
            .service(forward);
        BoxCloneSyncService::new(svc)
    }

    /// Composes only the shared, version-independent outer layers (trace →
    /// CORS plus the context stamp) around `service` — for versioned APIs,
    /// where `service` is the version dispatcher and the remaining layers
    /// live in per-version chains built with [`Self::build_inner`]. Any
    /// inner layers set on this builder are ignored.
    pub fn build_outer<S>(self, service: S) -> ChainService
    where
        S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let svc = ServiceBuilder::new()
            .option_layer(self.trace)
            .option_layer(self.metrics)
            .option_layer(self.stats)
            .option_layer(self.analytics)
            .layer(SetContextLayer::new(self.ctx))
            .option_layer(self.ip_filter)
            .option_layer(self.cors)
            .service(service);
        BoxCloneSyncService::new(svc)
    }

    /// Composes only the per-version inner layers (path policy → the api-id
    /// header) around `forward` — one such chain per version of a versioned
    /// API, dispatched to below a [`Self::build_outer`] stack. Any outer
    /// layers set on this builder are ignored (the context stamp included:
    /// the outer stack already applied it).
    pub fn build_inner<S>(self, forward: S) -> ChainService
    where
        S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let svc = ServiceBuilder::new()
            .option_layer(self.path_policy)
            .option_layer(self.size_limit)
            .option_layer(self.plugins_pre)
            .option_layer(self.auth)
            .option_layer(self.rate_limit)
            .option_layer(self.plugins_post)
            .option_layer(self.graphql)
            .option_layer(self.transform_headers)
            .option_layer(self.transform_body)
            .option_layer(self.mock)
            .option_layer(self.cache)
            .layer(ApiIdHeaderLayer::new())
            .service(forward);
        BoxCloneSyncService::new(svc)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::HeaderValue;
    use http_body_util::Full;
    use tower::ServiceExt;

    use super::*;
    use crate::API_ID_HEADER;

    fn body(text: &'static str) -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::from_static(text.as_bytes())))
    }

    /// Innermost stand-in for the forwarder: echoes the api-id header and the
    /// context extension back in response headers.
    async fn echo_forward(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let mut resp = Response::new(body("ok"));
        if let Some(v) = req.headers().get(API_ID_HEADER) {
            resp.headers_mut().insert("x-echo-api-id", v.clone());
        }
        if let Some(ctx) = req.extensions().get::<RequestContext>() {
            resp.headers_mut().insert(
                "x-echo-org-id",
                HeaderValue::from_str(ctx.org_id()).expect("test org id"),
            );
        }
        Ok(resp)
    }

    fn chain() -> ChainService {
        ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .build(tower::service_fn(echo_forward))
    }

    #[tokio::test]
    async fn chain_stamps_context_and_header_end_to_end() {
        let mut req = Request::new(body(""));
        // A client-supplied value must be overwritten, not forwarded.
        req.headers_mut()
            .insert(API_ID_HEADER, HeaderValue::from_static("spoofed"));

        let resp = chain().oneshot(req).await.expect("infallible");
        assert_eq!(
            resp.headers()
                .get("x-echo-api-id")
                .expect("api id")
                .as_bytes(),
            b"users-api"
        );
        assert_eq!(
            resp.headers()
                .get("x-echo-org-id")
                .expect("org id")
                .as_bytes(),
            b"acme"
        );
    }

    #[tokio::test]
    async fn transform_layer_applies_but_cannot_spoof_api_id() {
        let transforms: g2_core::HeaderTransforms = serde_json::from_str(
            r#"{
                "request": {"add": {"X-G2-Api-Id": "spoofed", "X-Env": "prod"}},
                "response": {"add": {"X-Gateway": "g2way"}}
            }"#,
        )
        .expect("valid transform JSON");
        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .transform_headers(Some(
                HeaderTransformLayer::from_config(&transforms, "users-api").expect("compiles"),
            ))
            .build(tower::service_fn(echo_forward));

        let resp = chain
            .oneshot(Request::new(body("")))
            .await
            .expect("infallible");
        // The anti-spoof stamp runs inside the transform layer and wins.
        assert_eq!(
            resp.headers()
                .get("x-echo-api-id")
                .expect("api id")
                .as_bytes(),
            b"users-api"
        );
        // Response transform applied on the way out.
        assert_eq!(
            resp.headers().get("x-gateway").expect("added").as_bytes(),
            b"g2way"
        );
    }

    #[tokio::test]
    async fn body_transform_runs_inside_header_transforms() {
        use http_body_util::BodyExt;

        let headers: g2_core::HeaderTransforms = serde_json::from_str(
            r#"{
                "request": {"add": {"X-Env": "prod"}},
                "response": {"add": {"Content-Type": "text/headers-win"}}
            }"#,
        )
        .expect("valid transform JSON");
        let bodies: g2_core::BodyTransforms = serde_json::from_str(
            r#"{
                "request": [{"pattern": "", "template": "{{ _g2.headers['x-env'] }}"}],
                "response": [{"pattern": "", "template": "{{ raw }}|reshaped"}]
            }"#,
        )
        .expect("valid transform JSON");

        /// Echoes the request body back as the response body.
        async fn echo_body(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
            let bytes = req.into_body().collect().await.expect("collect").to_bytes();
            Ok(Response::new(ProxyBody::new(Full::new(bytes))))
        }

        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .transform_headers(Some(
                HeaderTransformLayer::from_config(&headers, "users-api").expect("compiles"),
            ))
            .transform_body(
                BodyTransformLayer::from_config(&bodies, None, "users-api").expect("compiles"),
            )
            .build(tower::service_fn(echo_body));

        let resp = chain
            .oneshot(Request::new(body("orig")))
            .await
            .expect("infallible");
        // Response body transform applied; header transforms run after it on
        // the way out, so their Content-Type wins over the body rule's.
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_TYPE)
                .expect("content type")
                .as_bytes(),
            b"text/headers-win"
        );
        let out = resp
            .into_body()
            .collect()
            .await
            .expect("collect")
            .to_bytes();
        // "prod" proves the request body transform saw the header
        // transform's addition (the header layer runs first on the way in,
        // and the echo upstream reflected the transformed request body);
        // "|reshaped" proves the response rule ran on the way out.
        assert_eq!(&out[..], b"prod|reshaped");
    }

    #[tokio::test]
    async fn mock_responses_get_body_transforms() {
        use http_body_util::BodyExt;

        use crate::mock::MockResponseLayer;

        let bodies: g2_core::BodyTransforms = serde_json::from_str(
            r#"{"response": [{"pattern": "", "template": "{\"mocked\": {{ body.pong | tojson }}}"}]}"#,
        )
        .expect("valid transform JSON");
        let mock = MockResponseLayer::from_config(
            &[g2_core::MockResponse {
                pattern: "^/ping$".into(),
                methods: vec![],
                status: 200,
                body: r#"{"pong": true}"#.into(),
                headers: Default::default(),
            }],
            "users-api",
        )
        .expect("compiles")
        .expect("non-empty");

        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .transform_body(
                BodyTransformLayer::from_config(&bodies, None, "users-api").expect("compiles"),
            )
            .mock(Some(mock))
            .build(tower::service_fn(echo_forward));

        let req = Request::builder()
            .uri("/ping")
            .body(body(""))
            .expect("request");
        let resp = chain.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::OK);
        let out = resp
            .into_body()
            .collect()
            .await
            .expect("collect")
            .to_bytes();
        assert_eq!(&out[..], br#"{"mocked": true}"#);
    }

    #[tokio::test]
    async fn path_policy_auth_and_mock_interact_correctly() {
        use std::sync::Arc;

        use g2_core::{AuthConfig, MockResponse, PathRule};
        use g2_storage::SharedStorage;

        use crate::mock::MockResponseLayer;
        use crate::path_policy::PathPolicyLayer;

        let rule = |pattern: &str| PathRule {
            pattern: pattern.into(),
            methods: vec![],
        };
        // Token auth with an empty store: any authenticated request fails,
        // so a 200 proves auth was bypassed.
        let storage: SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
        let auth =
            AuthLayer::from_config(&AuthConfig::default(), storage, "users-api", "acme", None)
                .expect("valid")
                .expect("token mode");
        let path_policy = PathPolicyLayer::from_config(
            &[],
            &[rule("^/blocked$")],
            &[rule("^/ping$")],
            "users-api",
        )
        .expect("compiles")
        .expect("non-empty");
        let mock = MockResponseLayer::from_config(
            &[MockResponse {
                pattern: "^/mocked$".into(),
                methods: vec![],
                status: 299,
                body: String::new(),
                headers: Default::default(),
            }],
            "users-api",
        )
        .expect("compiles")
        .expect("non-empty");

        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .path_policy(Some(path_policy))
            .auth(Some(auth))
            .mock(Some(mock))
            .build(tower::service_fn(echo_forward));

        let call = |path: &str| {
            let req = Request::builder()
                .uri(path)
                .body(body(""))
                .expect("request");
            chain.clone().oneshot(req)
        };

        // Ignored path: no credentials, yet the upstream echo answers.
        let resp = call("/ping").await.expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(resp.headers().contains_key("x-echo-api-id"));

        // Blocked path: rejected before auth (403, not 401).
        let resp = call("/blocked").await.expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

        // Mock sits below auth: without credentials it is never reached.
        let resp = call("/mocked").await.expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        // Everything else still requires credentials.
        let resp = call("/other").await.expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn pre_plugins_run_before_auth_and_post_plugins_after() {
        use std::sync::Arc;

        use g2_core::AuthConfig;
        use g2_storage::SharedStorage;

        use crate::plugin::{HookKind, HookOutcome, PluginExec, PluginLayer};

        /// Answers every request with 418.
        struct Teapot;
        impl PluginExec for Teapot {
            fn name(&self) -> &str {
                "teapot"
            }
            fn run(
                &self,
                _call: &crate::plugin::HookInvocation<'_>,
            ) -> Result<HookOutcome, String> {
                let mut resp = http::Response::new(Bytes::new());
                *resp.status_mut() = http::StatusCode::IM_A_TEAPOT;
                Ok(HookOutcome::Respond(resp))
            }
        }

        // Token auth with an empty store: every authenticated request 401s,
        // so what the client sees reveals which side of auth the plugin ran.
        let auth = || {
            let storage: SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
            AuthLayer::from_config(&AuthConfig::default(), storage, "users-api", "acme", None)
                .expect("valid")
                .expect("token mode")
        };
        let plugin = |kind| PluginLayer::from_execs(kind, vec![Arc::new(Teapot)]);

        // Pre slot: the plugin answers before auth can reject.
        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .auth(Some(auth()))
            .plugins_pre(Some(plugin(HookKind::Pre)))
            .build(tower::service_fn(echo_forward));
        let resp = chain
            .oneshot(Request::new(body("")))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::IM_A_TEAPOT);

        // Post slot: auth rejects first, the plugin never runs.
        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .auth(Some(auth()))
            .plugins_post(Some(plugin(HookKind::Post)))
            .build(tower::service_fn(echo_forward));
        let resp = chain
            .oneshot(Request::new(body("")))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn plugins_cannot_spoof_the_api_id_header() {
        use std::sync::Arc;

        use crate::plugin::{HookKind, HookOutcome, PluginExec, PluginLayer};

        /// Sets the anti-spoof header on the request.
        struct Spoofer;
        impl PluginExec for Spoofer {
            fn name(&self) -> &str {
                "spoofer"
            }
            fn run(
                &self,
                _call: &crate::plugin::HookInvocation<'_>,
            ) -> Result<HookOutcome, String> {
                Ok(HookOutcome::Continue {
                    set_headers: vec![(API_ID_HEADER, HeaderValue::from_static("spoofed"))],
                    remove_headers: vec![],
                })
            }
        }

        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .plugins_post(Some(PluginLayer::from_execs(
                HookKind::Post,
                vec![Arc::new(Spoofer)],
            )))
            .build(tower::service_fn(echo_forward));
        let resp = chain
            .oneshot(Request::new(body("")))
            .await
            .expect("infallible");
        // The anti-spoof stamp is innermost and wins.
        assert_eq!(
            resp.headers()
                .get("x-echo-api-id")
                .expect("api id")
                .as_bytes(),
            b"users-api"
        );
    }

    #[tokio::test]
    async fn ignored_path_reaches_a_mock_without_credentials() {
        use g2_core::{MockResponse, PathRule};

        use crate::mock::MockResponseLayer;
        use crate::path_policy::PathPolicyLayer;

        let storage: g2_storage::SharedStorage =
            std::sync::Arc::new(g2_storage::MemoryStorage::new());
        let auth = AuthLayer::from_config(
            &g2_core::AuthConfig::default(),
            storage,
            "users-api",
            "acme",
            None,
        )
        .expect("valid")
        .expect("token mode");
        let path_policy = PathPolicyLayer::from_config(
            &[],
            &[],
            &[PathRule {
                pattern: "^/status$".into(),
                methods: vec![],
            }],
            "users-api",
        )
        .expect("compiles")
        .expect("non-empty");
        let mock = MockResponseLayer::from_config(
            &[MockResponse {
                pattern: "^/status$".into(),
                methods: vec![],
                status: 200,
                body: "up".into(),
                headers: Default::default(),
            }],
            "users-api",
        )
        .expect("compiles")
        .expect("non-empty");

        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .path_policy(Some(path_policy))
            .auth(Some(auth))
            .mock(Some(mock))
            .build(tower::service_fn(echo_forward));

        let req = Request::builder()
            .uri("/status")
            .body(body(""))
            .expect("request");
        let resp = chain.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::OK);
        // The mock answered, not the upstream echo.
        assert!(!resp.headers().contains_key("x-echo-api-id"));
    }

    #[tokio::test]
    async fn cors_preflight_and_rejections_work_on_a_protected_api() {
        use std::sync::Arc;

        use g2_core::CorsConfig;
        use g2_storage::SharedStorage;

        use crate::cors::CorsLayer;

        // Token auth with an empty store: every credentialed request fails.
        let storage: SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
        let auth = AuthLayer::from_config(
            &g2_core::AuthConfig::default(),
            storage,
            "users-api",
            "acme",
            None,
        )
        .expect("valid")
        .expect("token mode");
        let cors: CorsConfig =
            serde_json::from_str(r#"{"allowed_origins": ["https://app.example.com"]}"#)
                .expect("valid CORS JSON");
        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .cors(Some(
                CorsLayer::from_config(&cors, "users-api").expect("compiles"),
            ))
            .auth(Some(auth))
            .build(tower::service_fn(echo_forward));

        // Preflight is answered above auth: no credentials needed.
        let req = Request::builder()
            .method(http::Method::OPTIONS)
            .uri("/x")
            .header("origin", "https://app.example.com")
            .header("access-control-request-method", "GET")
            .body(body(""))
            .expect("request");
        let resp = chain.clone().oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);
        assert!(resp.headers().contains_key("access-control-allow-origin"));

        // An uncredentialed actual request is rejected by auth, but the
        // 401 still carries CORS headers so browsers can read it.
        let req = Request::builder()
            .uri("/x")
            .header("origin", "https://app.example.com")
            .body(body(""))
            .expect("request");
        let resp = chain.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get("access-control-allow-origin")
                .expect("cors on rejection")
                .as_bytes(),
            b"https://app.example.com"
        );
    }

    #[tokio::test]
    async fn graphql_sits_below_auth() {
        use std::sync::Arc;

        use g2_storage::SharedStorage;

        use crate::graphql::GraphQlLayer;

        // Token auth with an empty store: every request without a valid key
        // is rejected — proving the GraphQL layer (which would answer 400
        // for this junk body) never ran.
        let storage: SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
        let auth = AuthLayer::from_config(
            &g2_core::AuthConfig::default(),
            storage,
            "users-api",
            "acme",
            None,
        )
        .expect("valid")
        .expect("token mode");
        let def: g2_core::ApiDefinition = serde_json::from_str(
            r#"{
                "api_id": "users-api",
                "name": "users-api",
                "listen_path": "/gql/",
                "target_url": "http://gql.internal",
                "graphql": { "schema": "type Query { hello: String }" }
            }"#,
        )
        .expect("valid definition");
        let graphql = GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def, None)
            .expect("compiles")
            .expect("enabled");

        let chain = ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .auth(Some(auth))
            .graphql(Some(graphql))
            .build(tower::service_fn(echo_forward));

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/gql")
            .body(body("not graphql"))
            .expect("request");
        let resp = chain.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn chain_clones_serve_independent_requests() {
        let chain = chain();
        for _ in 0..2 {
            let resp = chain
                .clone()
                .oneshot(Request::new(body("")))
                .await
                .expect("infallible");
            assert_eq!(
                resp.headers()
                    .get("x-echo-api-id")
                    .expect("api id")
                    .as_bytes(),
                b"users-api"
            );
        }
    }
}
