//! Rate-limit and quota enforcement: turn an API's endpoint limits and a
//! session's allowances into `429`/`403` rejections.
//!
//! [`RateLimitLayer`] sits after [`AuthLayer`](crate::AuthLayer) and reads
//! the [`SessionContext`] it stamped. The session checks skip requests
//! whose session carries no [`rate`](g2_core::KeySession::rate) and no
//! [`quota`](g2_core::KeySession::quota), and requests without a session;
//! API-level [`EndpointLimits`] need no session, which is why a keyless
//! API that declares them gets this layer too.
//!
//! Enforcement order, cheapest-shared-state first:
//!
//! 0. **Endpoint limits** (optional, [`EndpointLimits`]): the first rule
//!    matching the request's method and full client path is checked via
//!    [`Storage::check_rate`](g2_storage::Storage::check_rate) on an
//!    **aggregate** counter (all clients combined), denial → `429`. Runs
//!    before every session check, so an endpoint-denied request consumes
//!    no session allowance — and it applies even on `ignore_auth_paths`
//!    matches and keyless APIs.
//! 1. **Spike guard** (optional, pod-local): an exhausted local token
//!    bucket rejects with `429` before any Redis round-trip. Guards only
//!    the session checks — it keys on the session identity.
//! 2. **Rate** ([`Storage::check_rate`](g2_storage::Storage::check_rate)):
//!    sliding window, denial → `429` with the `X-RateLimit-*` headers and
//!    `Retry-After`.
//! 3. **Quota** ([`Storage::check_quota`](g2_storage::Storage::check_quota)):
//!    fixed period, denial → `403`
//!    "quota exceeded" with the same headers. A rate-denied
//!    request never consumes quota.
//!
//! Session counters are **per key** (`g2:{org}:ratelimit:{key_hash}` /
//! `g2:{org}:quota:{key_hash}`), shared across every API the key may
//! call. JWT and basic-auth identities use their virtual hashes
//! (`jwt:{identity}` / `basic:{username}`), so they get the same treatment.
//! Endpoint counters are per rule (`g2:{org}:endpointrl:{scope}:{index}`,
//! `scope` = api id or `{api_id}:{version}`), keyed by nothing
//! client-specific.
//!
//! **Fail-open**: if the storage backend errors, the request is allowed
//! and the failure logged loudly. Limits protect capacity; they are not
//! authorization, and a Redis outage must not take all JWT traffic down
//! with it (token/basic auth already fail closed in the auth layer, which
//! needs storage to resolve the session at all).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use g2_core::endpoints::endpoint_rate_limit_storage_key;
use g2_core::session::{quota_storage_key, rate_limit_storage_key};
use g2_core::{EndpointRateLimit, Error};
use g2_storage::{LimitDecision, SharedStorage};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use regex::Regex;
use tower::{Layer, Service};

use crate::auth::unix_now_secs;
use crate::context::SessionContext;
use crate::response::json_error;
use crate::spike::SpikeGuard;
use crate::ProxyBody;

/// `X-RateLimit-Limit`: the limit that produced this response.
pub const X_RATE_LIMIT_LIMIT: &str = "x-ratelimit-limit";
/// `X-RateLimit-Remaining`: requests left before the limit.
pub const X_RATE_LIMIT_REMAINING: &str = "x-ratelimit-remaining";
/// `X-RateLimit-Reset`: Unix timestamp (seconds) when the limit frees up.
pub const X_RATE_LIMIT_RESET: &str = "x-ratelimit-reset";

/// One compiled endpoint rule: prebuilt regex and method filter plus the
/// allowance and the rule's aggregate counter key, all fixed at build time.
#[derive(Debug)]
struct CompiledEndpointLimit {
    regex: Regex,
    /// Methods the rule applies to; empty = every method.
    methods: Vec<Method>,
    requests: u64,
    window: Duration,
    storage_key: String,
}

impl CompiledEndpointLimit {
    fn matches(&self, method: &Method, path: &str) -> bool {
        (self.methods.is_empty() || self.methods.contains(method)) && self.regex.is_match(path)
    }
}

/// One API's (or version's) compiled endpoint rate limits — the aggregate,
/// sessionless half of [`RateLimitLayer`]. See [`EndpointRateLimit`] for
/// the semantics.
#[derive(Debug)]
pub struct EndpointLimits {
    rules: Vec<CompiledEndpointLimit>,
}

impl EndpointLimits {
    /// Compiles the configured rules, or `None` when there are none.
    /// `scope` namespaces the counters: the API id, or `{api_id}:{version}`
    /// for one version of a versioned API.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a pattern or method
    /// does not compile. Definitions are validated before routes are built,
    /// so this failing indicates a validation gap, but the route build
    /// surfaces it loudly rather than panicking.
    pub fn from_config(
        rules: &[EndpointRateLimit],
        api_id: &str,
        org_id: &str,
        scope: &str,
    ) -> Result<Option<Self>, Error> {
        if rules.is_empty() {
            return Ok(None);
        }
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api_id.to_owned(),
            reason,
        };
        let rules = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                let regex = Regex::new(&rule.pattern).map_err(|e| {
                    fail(format!(
                        "invalid endpoint rate-limit regex `{}`: {e}",
                        rule.pattern
                    ))
                })?;
                let methods = rule
                    .methods
                    .iter()
                    .map(|m| {
                        Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                            .map_err(|_| fail(format!("invalid endpoint rate-limit method `{m}`")))
                    })
                    .collect::<Result<_, _>>()?;
                Ok(CompiledEndpointLimit {
                    regex,
                    methods,
                    requests: rule.rate.requests,
                    window: Duration::from_secs(rule.rate.per_seconds),
                    storage_key: endpoint_rate_limit_storage_key(org_id, scope, index),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Some(Self { rules }))
    }

    /// The first rule matching the request, if any (rule order decides —
    /// like mock responses).
    fn first_match(&self, method: &Method, path: &str) -> Option<&CompiledEndpointLimit> {
        self.rules.iter().find(|r| r.matches(method, path))
    }
}

/// Everything one API's rate limiting needs, precomputed at route-build time.
struct RateLimitState {
    api_id: Arc<str>,
    storage: SharedStorage,
    spike_guard: Option<Arc<SpikeGuard>>,
    endpoint_limits: Option<EndpointLimits>,
}

impl std::fmt::Debug for RateLimitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitState")
            .field("api_id", &self.api_id)
            .field("spike_guard", &self.spike_guard.is_some())
            .finish_non_exhaustive()
    }
}

/// Tower layer enforcing a session's rate and quota allowances.
#[derive(Debug, Clone)]
pub struct RateLimitLayer {
    state: Arc<RateLimitState>,
}

impl RateLimitLayer {
    /// Builds the layer for one API. `spike_guard` is the process-wide
    /// guard (or `None` when disabled in the gateway config);
    /// `endpoint_limits` the API's compiled endpoint rules (or `None` when
    /// it declares none).
    #[must_use]
    pub fn new(
        api_id: &str,
        storage: SharedStorage,
        spike_guard: Option<Arc<SpikeGuard>>,
        endpoint_limits: Option<EndpointLimits>,
    ) -> Self {
        Self {
            state: Arc::new(RateLimitState {
                api_id: api_id.into(),
                storage,
                spike_guard,
                endpoint_limits,
            }),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimit {
            inner,
            state: Arc::clone(&self.state),
        }
    }
}

/// The [`Service`] produced by [`RateLimitLayer`].
#[derive(Debug, Clone)]
pub struct RateLimit<S> {
    inner: S,
    state: Arc<RateLimitState>,
}

impl<S> Service<Request<ProxyBody>> for RateLimit<S>
where
    S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ProxyBody>) -> Self::Future {
        let state = Arc::clone(&self.state);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            match enforce(&state, &req).await {
                Ok(()) => inner.call(req).await,
                Err(resp) => Ok(resp),
            }
        })
    }
}

/// Runs the checks; `Err` is the ready-to-send rejection.
async fn enforce(
    state: &RateLimitState,
    req: &Request<ProxyBody>,
) -> Result<(), Response<ProxyBody>> {
    // Endpoint limits first: they are aggregate (no session), and a request
    // they deny must not consume any session allowance.
    if let Some(limits) = &state.endpoint_limits {
        if let Some(rule) = limits.first_match(req.method(), req.uri().path()) {
            match state
                .storage
                .check_rate(&rule.storage_key, rule.requests, rule.window)
                .await
            {
                Ok(decision) if !decision.allowed => {
                    return Err(limit_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate limit exceeded",
                        rule.requests,
                        &decision,
                    ));
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(
                        api_id = %state.api_id,
                        error = %e,
                        "endpoint rate check failed; failing open"
                    );
                }
            }
        }
    }

    let Some(ctx) = req.extensions().get::<SessionContext>() else {
        return Ok(());
    };
    let session = ctx.session();
    let (rate, quota) = (session.rate, session.quota);
    if rate.is_none() && quota.is_none() {
        return Ok(());
    }
    let identity = ctx.key_hash();

    if let Some(guard) = &state.spike_guard {
        if !guard.try_acquire(identity) {
            tracing::debug!(api_id = %state.api_id, "spike guard rejected request locally");
            // The guard knows no distributed state; advertise the rate (or
            // quota) limit with a one-second retry hint.
            let limit = rate.map_or_else(|| quota.map_or(0, |q| q.max), |r| r.requests);
            let decision = LimitDecision {
                allowed: false,
                remaining: 0,
                reset_after: Duration::from_secs(1),
            };
            return Err(limit_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
                limit,
                &decision,
            ));
        }
    }

    if let Some(rate) = rate {
        let key = rate_limit_storage_key(&session.org_id, identity);
        let window = Duration::from_secs(rate.per_seconds);
        match state.storage.check_rate(&key, rate.requests, window).await {
            Ok(decision) if !decision.allowed => {
                return Err(limit_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate limit exceeded",
                    rate.requests,
                    &decision,
                ));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(
                    api_id = %state.api_id,
                    error = %e,
                    "rate check failed; failing open"
                );
            }
        }
    }

    if let Some(quota) = quota {
        let key = quota_storage_key(&session.org_id, identity);
        let period = Duration::from_secs(quota.renewal_rate_secs);
        match state.storage.check_quota(&key, quota.max, period).await {
            Ok(decision) if !decision.allowed => {
                // Quota exhaustion answers 403, not 429: the key
                // has spent its allowance, waiting a moment will not help.
                return Err(limit_response(
                    StatusCode::FORBIDDEN,
                    "quota exceeded",
                    quota.max,
                    &decision,
                ));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(
                    api_id = %state.api_id,
                    error = %e,
                    "quota check failed; failing open"
                );
            }
        }
    }

    Ok(())
}

/// A denial with the `X-RateLimit-*` headers and a `Retry-After` hint.
fn limit_response(
    status: StatusCode,
    message: &str,
    limit: u64,
    decision: &LimitDecision,
) -> Response<ProxyBody> {
    // Ceil to whole seconds so "wait this long" is never an underestimate.
    let reset_secs = u64::try_from(decision.reset_after.as_millis().div_ceil(1000))
        .unwrap_or(u64::MAX)
        .max(1);
    let mut resp = json_error(status, message);
    let headers = resp.headers_mut();
    let num = |v: u64| HeaderValue::from_str(&v.to_string()).expect("integer header value");
    headers.insert(X_RATE_LIMIT_LIMIT, num(limit));
    headers.insert(X_RATE_LIMIT_REMAINING, num(decision.remaining));
    // The reset is reported as an absolute Unix timestamp.
    headers.insert(
        X_RATE_LIMIT_RESET,
        num(unix_now_secs().saturating_add(reset_secs)),
    );
    headers.insert(http::header::RETRY_AFTER, num(reset_secs));
    resp
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use bytes::Bytes;
    use g2_core::session::{hash_key, RateLimit as Rate};
    use g2_core::{KeySession, SpikeGuardConfig};
    use g2_storage::{MemoryStorage, Storage, StorageError};
    use http_body_util::Full;
    use tower::ServiceExt;

    use super::*;

    const API: &str = "users-api";

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    async fn ok_inner(_req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        Ok(Response::new(body()))
    }

    fn service(storage: SharedStorage, guard: Option<Arc<SpikeGuard>>) -> crate::ChainService {
        service_with_endpoints(storage, guard, None)
    }

    fn service_with_endpoints(
        storage: SharedStorage,
        guard: Option<Arc<SpikeGuard>>,
        endpoint_limits: Option<EndpointLimits>,
    ) -> crate::ChainService {
        let layer = RateLimitLayer::new(API, storage, guard, endpoint_limits);
        crate::ChainService::new(layer.layer(tower::service_fn(ok_inner)))
    }

    fn request_with_session(session: KeySession) -> Request<ProxyBody> {
        let mut req = Request::builder().uri("/x").body(body()).expect("request");
        req.extensions_mut()
            .insert(SessionContext::new(session, hash_key("test-key")));
        req
    }

    fn rated_session(requests: u64, per_seconds: u64) -> KeySession {
        KeySession {
            rate: Some(Rate {
                requests,
                per_seconds,
            }),
            ..KeySession::default()
        }
    }

    #[tokio::test]
    async fn no_session_passes_through() {
        let svc = service(Arc::new(MemoryStorage::new()), None);
        let req = Request::builder().uri("/x").body(body()).expect("request");
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unlimited_session_passes_through() {
        let svc = service(Arc::new(MemoryStorage::new()), None);
        let resp = svc
            .oneshot(request_with_session(KeySession::default()))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rate_denial_is_429_with_headers() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());

        for _ in 0..2 {
            let resp = service(Arc::clone(&storage), None)
                .oneshot(request_with_session(rated_session(2, 60)))
                .await
                .expect("infallible");
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = service(storage, None)
            .oneshot(request_with_session(rated_session(2, 60)))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        let header = |name: &str| {
            resp.headers()
                .get(name)
                .unwrap_or_else(|| panic!("`{name}` header"))
                .to_str()
                .expect("ascii")
                .to_owned()
        };
        assert_eq!(header(X_RATE_LIMIT_LIMIT), "2");
        assert_eq!(header(X_RATE_LIMIT_REMAINING), "0");
        let reset: u64 = header(X_RATE_LIMIT_RESET).parse().expect("number");
        assert!(reset >= unix_now_secs(), "reset is an absolute timestamp");
        let retry: u64 = header("retry-after").parse().expect("number");
        assert!((1..=60).contains(&retry));
    }

    #[tokio::test]
    async fn quota_denial_is_403_with_headers() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let session = || KeySession {
            quota: Some(g2_core::session::Quota {
                max: 1,
                renewal_rate_secs: 3600,
            }),
            ..KeySession::default()
        };

        let resp = service(Arc::clone(&storage), None)
            .oneshot(request_with_session(session()))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = service(storage, None)
            .oneshot(request_with_session(session()))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get(X_RATE_LIMIT_LIMIT)
                .expect("limit header")
                .as_bytes(),
            b"1"
        );
    }

    #[tokio::test]
    async fn distinct_keys_do_not_share_counters() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let request_as = |raw_key: &str| {
            let mut req = Request::builder().uri("/x").body(body()).expect("request");
            req.extensions_mut()
                .insert(SessionContext::new(rated_session(1, 60), hash_key(raw_key)));
            req
        };

        let resp = service(Arc::clone(&storage), None)
            .oneshot(request_as("key-a"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = service(Arc::clone(&storage), None)
            .oneshot(request_as("key-a"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "a exhausted");
        let resp = service(storage, None)
            .oneshot(request_as("key-b"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK, "b unaffected");
    }

    #[tokio::test]
    async fn spike_guard_rejects_before_storage() {
        /// A storage that panics if any limit check reaches it.
        #[derive(Debug)]
        struct NoLimitCalls(MemoryStorage);

        #[async_trait]
        impl Storage for NoLimitCalls {
            async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
                self.0.get(key).await
            }
            async fn set(
                &self,
                key: &str,
                value: &str,
                ttl: Option<Duration>,
            ) -> Result<(), StorageError> {
                self.0.set(key, value, ttl).await
            }
            async fn delete(&self, key: &str) -> Result<bool, StorageError> {
                self.0.delete(key).await
            }
            async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
                self.0.scan_prefix(prefix).await
            }
            async fn list_append(
                &self,
                key: &str,
                values: &[String],
                max_len: Option<u64>,
            ) -> Result<(), StorageError> {
                self.0.list_append(key, values, max_len).await
            }
            async fn list_drain(&self, key: &str, max: usize) -> Result<Vec<String>, StorageError> {
                self.0.list_drain(key, max).await
            }
            async fn publish(&self, channel: &str, payload: &str) -> Result<(), StorageError> {
                self.0.publish(channel, payload).await
            }
            async fn subscribe(
                &self,
                channel: &str,
            ) -> Result<tokio::sync::mpsc::Receiver<String>, StorageError> {
                self.0.subscribe(channel).await
            }
            async fn check_rate(
                &self,
                _key: &str,
                _limit: u64,
                _window: Duration,
            ) -> Result<LimitDecision, StorageError> {
                panic!("spike-guarded request must not reach storage");
            }
            async fn check_quota(
                &self,
                _key: &str,
                _max: u64,
                _period: Duration,
            ) -> Result<LimitDecision, StorageError> {
                panic!("spike-guarded request must not reach storage");
            }
        }

        let guard = Arc::new(SpikeGuard::new(&SpikeGuardConfig {
            capacity: 1,
            refill_per_sec: 1,
        }));

        // First request drains the guard (through a real storage).
        let plain: SharedStorage = Arc::new(MemoryStorage::new());
        let resp = service(plain, Some(Arc::clone(&guard)))
            .oneshot(request_with_session(rated_session(10, 60)))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);

        // Guard now empty: rejection must happen before any storage call —
        // the sentinel storage panics if a limit check reaches it.
        let sentinel: SharedStorage = Arc::new(NoLimitCalls(MemoryStorage::new()));
        let resp = service(sentinel, Some(guard))
            .oneshot(request_with_session(rated_session(10, 60)))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key("retry-after"));
    }

    /// A storage whose limit checks always error.
    #[derive(Debug)]
    struct BrokenLimits;

    #[async_trait]
    impl Storage for BrokenLimits {
        async fn get(&self, _key: &str) -> Result<Option<String>, StorageError> {
            Ok(None)
        }
        async fn set(
            &self,
            _key: &str,
            _value: &str,
            _ttl: Option<Duration>,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        async fn delete(&self, _key: &str) -> Result<bool, StorageError> {
            Ok(false)
        }
        async fn scan_prefix(&self, _prefix: &str) -> Result<Vec<String>, StorageError> {
            Ok(Vec::new())
        }
        async fn list_append(
            &self,
            _key: &str,
            _values: &[String],
            _max_len: Option<u64>,
        ) -> Result<(), StorageError> {
            Err(StorageError::Backend("redis is down".into()))
        }
        async fn list_drain(&self, _key: &str, _max: usize) -> Result<Vec<String>, StorageError> {
            Err(StorageError::Backend("redis is down".into()))
        }
        async fn publish(&self, _channel: &str, _payload: &str) -> Result<(), StorageError> {
            Err(StorageError::Backend("redis is down".into()))
        }
        async fn subscribe(
            &self,
            _channel: &str,
        ) -> Result<tokio::sync::mpsc::Receiver<String>, StorageError> {
            Err(StorageError::Backend("redis is down".into()))
        }
        async fn check_rate(
            &self,
            _key: &str,
            _limit: u64,
            _window: Duration,
        ) -> Result<LimitDecision, StorageError> {
            Err(StorageError::Backend("redis is down".into()))
        }
        async fn check_quota(
            &self,
            _key: &str,
            _max: u64,
            _period: Duration,
        ) -> Result<LimitDecision, StorageError> {
            Err(StorageError::Backend("redis is down".into()))
        }
    }

    #[tokio::test]
    async fn storage_failure_fails_open() {
        let resp = service(Arc::new(BrokenLimits), None)
            .oneshot(request_with_session(rated_session(1, 60)))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK, "limits fail open");
    }

    fn endpoint_rule(
        pattern: &str,
        methods: &[&str],
        requests: u64,
        per_seconds: u64,
    ) -> EndpointRateLimit {
        EndpointRateLimit {
            pattern: pattern.into(),
            methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            rate: Rate {
                requests,
                per_seconds,
            },
        }
    }

    fn compiled(rules: &[EndpointRateLimit]) -> Option<EndpointLimits> {
        EndpointLimits::from_config(rules, API, "default", API).expect("rules compile")
    }

    fn bare_request(method: &str, path: &str) -> Request<ProxyBody> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(body())
            .expect("request")
    }

    #[tokio::test]
    async fn endpoint_limit_applies_without_session() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let rules = [endpoint_rule("^/limited", &[], 1, 60)];

        let resp = service_with_endpoints(Arc::clone(&storage), None, compiled(&rules))
            .oneshot(bare_request("GET", "/limited"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = service_with_endpoints(storage, None, compiled(&rules))
            .oneshot(bare_request("GET", "/limited"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(X_RATE_LIMIT_LIMIT)
                .expect("limit header")
                .as_bytes(),
            b"1"
        );
        assert!(resp.headers().contains_key("retry-after"));
    }

    #[tokio::test]
    async fn endpoint_counter_is_aggregate_across_identities() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let rules = [endpoint_rule("^/limited", &[], 1, 60)];
        let request_as = |raw_key: &str| {
            let mut req = bare_request("GET", "/limited");
            req.extensions_mut().insert(SessionContext::new(
                KeySession::default(),
                hash_key(raw_key),
            ));
            req
        };

        let resp = service_with_endpoints(Arc::clone(&storage), None, compiled(&rules))
            .oneshot(request_as("key-a"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = service_with_endpoints(storage, None, compiled(&rules))
            .oneshot(request_as("key-b"))
            .await
            .expect("infallible");
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "different keys share the aggregate endpoint counter"
        );
    }

    #[tokio::test]
    async fn first_matching_endpoint_rule_wins() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let rules = [
            endpoint_rule("^/a", &[], 1, 60),
            endpoint_rule("^/a|^/b", &[], 100, 60),
        ];

        let svc = |storage: &SharedStorage| {
            service_with_endpoints(Arc::clone(storage), None, compiled(&rules))
        };
        let resp = svc(&storage)
            .oneshot(bare_request("GET", "/a"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = svc(&storage)
            .oneshot(bare_request("GET", "/a"))
            .await
            .expect("infallible");
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "rule order decides: the generous second rule never sees /a"
        );
        let resp = svc(&storage)
            .oneshot(bare_request("GET", "/b"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK, "/b matches only rule 2");
    }

    #[tokio::test]
    async fn endpoint_method_filter_and_unmatched_paths_pass() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let rules = [endpoint_rule("^/posts", &["POST"], 1, 60)];
        let svc = |storage: &SharedStorage| {
            service_with_endpoints(Arc::clone(storage), None, compiled(&rules))
        };

        for _ in 0..2 {
            let resp = svc(&storage)
                .oneshot(bare_request("GET", "/posts"))
                .await
                .expect("infallible");
            assert_eq!(resp.status(), StatusCode::OK, "GET is not limited");
        }
        let resp = svc(&storage)
            .oneshot(bare_request("POST", "/posts"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = svc(&storage)
            .oneshot(bare_request("POST", "/posts"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let resp = svc(&storage)
            .oneshot(bare_request("POST", "/elsewhere"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK, "unmatched path unlimited");
    }

    #[tokio::test]
    async fn endpoint_denial_spares_session_limits() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let rules = [endpoint_rule("^/limited", &[], 1, 60)];
        let request_to = |path: &str| {
            let mut req = bare_request("GET", path);
            req.extensions_mut()
                .insert(SessionContext::new(rated_session(2, 60), hash_key("key")));
            req
        };
        let svc = |storage: &SharedStorage| {
            service_with_endpoints(Arc::clone(storage), None, compiled(&rules))
        };

        // Consumes the endpoint slot and one of two session slots.
        let resp = svc(&storage)
            .oneshot(request_to("/limited"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        // Endpoint-denied: must not consume the second session slot.
        let resp = svc(&storage)
            .oneshot(request_to("/limited"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        // The spared session slot admits this request…
        let resp = svc(&storage)
            .oneshot(request_to("/elsewhere"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK, "session slot was spared");
        // …and the session limit still works after it.
        let resp = svc(&storage)
            .oneshot(request_to("/elsewhere"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn session_checks_still_run_after_endpoint_pass() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let rules = [endpoint_rule("^/x", &[], 100, 60)];
        let request = || {
            let mut req = bare_request("GET", "/x");
            req.extensions_mut()
                .insert(SessionContext::new(rated_session(1, 60), hash_key("key")));
            req
        };

        let resp = service_with_endpoints(Arc::clone(&storage), None, compiled(&rules))
            .oneshot(request())
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = service_with_endpoints(storage, None, compiled(&rules))
            .oneshot(request())
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn endpoint_check_fails_open() {
        let rules = [endpoint_rule("^/limited", &[], 1, 60)];
        let resp = service_with_endpoints(Arc::new(BrokenLimits), None, compiled(&rules))
            .oneshot(bare_request("GET", "/limited"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK, "endpoint limits fail open");
    }

    #[test]
    fn endpoint_limits_from_config() {
        assert!(
            EndpointLimits::from_config(&[], API, "default", API)
                .expect("empty is fine")
                .is_none(),
            "no rules, no limits"
        );

        let err =
            EndpointLimits::from_config(&[endpoint_rule("(", &[], 1, 60)], API, "default", API)
                .unwrap_err()
                .to_string();
        assert!(err.contains("endpoint rate-limit regex"), "got: {err}");
    }
}
