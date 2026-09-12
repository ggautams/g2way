//! Rate-limit and quota enforcement: turn a session's allowances into
//! `429`/`403` rejections.
//!
//! [`RateLimitLayer`] sits after [`AuthLayer`](crate::AuthLayer) and reads
//! the [`SessionContext`] it stamped. Requests whose session carries no
//! [`rate`](g2_core::KeySession::rate) and no
//! [`quota`](g2_core::KeySession::quota) pass through untouched, as do
//! requests without a session (keyless APIs never get this layer anyway).
//!
//! Enforcement order, cheapest first:
//!
//! 1. **Spike guard** (optional, pod-local): an exhausted local token
//!    bucket rejects with `429` before any Redis round-trip.
//! 2. **Rate** ([`Storage::check_rate`](g2_storage::Storage::check_rate)):
//!    sliding window, denial → `429` with the `X-RateLimit-*` headers and
//!    `Retry-After`.
//! 3. **Quota** ([`Storage::check_quota`](g2_storage::Storage::check_quota)):
//!    fixed period, denial → `403`
//!    "quota exceeded" with the same headers. A rate-denied
//!    request never consumes quota.
//!
//! Counters are **per key** (`g2:{org}:ratelimit:{key_hash}` /
//! `g2:{org}:quota:{key_hash}`), shared across every API the key may
//! call. JWT and basic-auth identities use their virtual hashes
//! (`jwt:{identity}` / `basic:{username}`), so they get the same treatment.
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

use g2_core::session::{quota_storage_key, rate_limit_storage_key};
use g2_storage::{LimitDecision, SharedStorage};
use http::{HeaderValue, Request, Response, StatusCode};
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

/// Everything one API's rate limiting needs, precomputed at route-build time.
struct RateLimitState {
    api_id: Arc<str>,
    storage: SharedStorage,
    spike_guard: Option<Arc<SpikeGuard>>,
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
    /// guard (or `None` when disabled in the gateway config).
    #[must_use]
    pub fn new(api_id: &str, storage: SharedStorage, spike_guard: Option<Arc<SpikeGuard>>) -> Self {
        Self {
            state: Arc::new(RateLimitState {
                api_id: api_id.into(),
                storage,
                spike_guard,
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
        let layer = RateLimitLayer::new(API, storage, guard);
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

    #[tokio::test]
    async fn storage_failure_fails_open() {
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

        let resp = service(Arc::new(BrokenLimits), None)
            .oneshot(request_with_session(rated_session(1, 60)))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK, "limits fail open");
    }
}
