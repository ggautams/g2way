//! Per-API request counters for the dashboard-support API.
//!
//! [`StatsLayer`] sits outermost in an API's chain and bumps lock-free
//! atomic counters ([`ApiStats`]) on every response — auth rejections and
//! rate-limit denials included, since a dashboard wants to see those too.
//! Counters live in a process-wide [`StatsRegistry`] keyed by `api_id`, so
//! they survive route-table reloads; they reset on process restart
//! (cluster-wide, durable analytics are milestone M5's `AnalyticsSink`).

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use http::{Request, Response};
use serde::Serialize;
use tower::{Layer, Service};

use crate::ProxyBody;

/// Lock-free counters for one API. All increments are `Relaxed`: counters
/// are independent and a snapshot only needs to be approximately
/// consistent.
#[derive(Debug, Default)]
pub struct ApiStats {
    requests: AtomicU64,
    /// Responses by status class; index 0 = 1xx … index 4 = 5xx.
    classes: [AtomicU64; 5],
}

impl ApiStats {
    fn record(&self, status: http::StatusCode) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let class = (status.as_u16() / 100) as usize;
        if let Some(counter) = self.classes.get(class.wrapping_sub(1)) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A point-in-time copy of one API's counters, ready to serialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiStatsSnapshot {
    /// The API the counters belong to.
    pub api_id: String,
    /// Total requests handled (every response counts, whatever the status).
    pub requests: u64,
    /// 1xx responses.
    pub status_1xx: u64,
    /// 2xx responses.
    pub status_2xx: u64,
    /// 3xx responses.
    pub status_3xx: u64,
    /// 4xx responses (including auth rejections and 429s).
    pub status_4xx: u64,
    /// 5xx responses (upstream failures included).
    pub status_5xx: u64,
}

/// Process-wide registry of per-API counters.
///
/// Route-table builds call [`for_api`](Self::for_api) so a rebuilt route
/// keeps counting into the same [`ApiStats`]; the mutex is touched only at
/// build and snapshot time, never per request.
#[derive(Debug, Default)]
pub struct StatsRegistry {
    inner: Mutex<HashMap<String, Arc<ApiStats>>>,
}

impl StatsRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The counters for `api_id`, created on first use.
    #[must_use]
    pub fn for_api(&self, api_id: &str) -> Arc<ApiStats> {
        let mut inner = self.inner.lock().expect("stats registry lock poisoned");
        Arc::clone(inner.entry(api_id.to_owned()).or_default())
    }

    /// Snapshots every API's counters, sorted by `api_id`.
    ///
    /// APIs appear once they have a route built with stats enabled, even
    /// before their first request.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ApiStatsSnapshot> {
        let inner = self.inner.lock().expect("stats registry lock poisoned");
        let mut snaps: Vec<ApiStatsSnapshot> = inner
            .iter()
            .map(|(api_id, stats)| {
                let class = |i: usize| stats.classes[i].load(Ordering::Relaxed);
                ApiStatsSnapshot {
                    api_id: api_id.clone(),
                    requests: stats.requests.load(Ordering::Relaxed),
                    status_1xx: class(0),
                    status_2xx: class(1),
                    status_3xx: class(2),
                    status_4xx: class(3),
                    status_5xx: class(4),
                }
            })
            .collect();
        snaps.sort_by(|a, b| a.api_id.cmp(&b.api_id));
        snaps
    }
}

/// Tower layer recording every response of one API into its [`ApiStats`].
#[derive(Debug, Clone)]
pub struct StatsLayer {
    stats: Arc<ApiStats>,
}

impl StatsLayer {
    /// Builds the layer counting into `stats`.
    #[must_use]
    pub fn new(stats: Arc<ApiStats>) -> Self {
        Self { stats }
    }
}

impl<S> Layer<S> for StatsLayer {
    type Service = Stats<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Stats {
            inner,
            stats: Arc::clone(&self.stats),
        }
    }
}

/// The [`Service`] produced by [`StatsLayer`].
#[derive(Debug, Clone)]
pub struct Stats<S> {
    inner: S,
    stats: Arc<ApiStats>,
}

impl<S> Service<Request<ProxyBody>> for Stats<S>
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
        let stats = Arc::clone(&self.stats);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let resp = inner.call(req).await?;
            stats.record(resp.status());
            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::StatusCode;
    use http_body_util::Full;
    use tower::ServiceExt;

    use super::*;

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    async fn respond(status: StatusCode, stats: &Arc<ApiStats>) {
        let svc = StatsLayer::new(Arc::clone(stats)).layer(tower::service_fn(
            move |_req: Request<ProxyBody>| async move {
                let mut resp = Response::new(body());
                *resp.status_mut() = status;
                Ok::<_, Infallible>(resp)
            },
        ));
        svc.oneshot(Request::new(body())).await.expect("infallible");
    }

    #[tokio::test]
    async fn counts_requests_by_status_class() {
        let registry = StatsRegistry::new();
        let stats = registry.for_api("users");
        respond(StatusCode::OK, &stats).await;
        respond(StatusCode::CREATED, &stats).await;
        respond(StatusCode::FORBIDDEN, &stats).await;
        respond(StatusCode::BAD_GATEWAY, &stats).await;

        let snap = registry.snapshot();
        assert_eq!(snap.len(), 1);
        let s = &snap[0];
        assert_eq!(
            (s.requests, s.status_2xx, s.status_4xx, s.status_5xx),
            (4, 2, 1, 1),
            "snapshot: {s:?}"
        );
        assert_eq!(s.status_1xx + s.status_3xx, 0);
    }

    #[tokio::test]
    async fn registry_reuses_counters_across_rebuilds_and_sorts_snapshots() {
        let registry = StatsRegistry::new();
        respond(StatusCode::OK, &registry.for_api("zeta")).await;
        // A "rebuild": for_api again must return the same counters.
        respond(StatusCode::OK, &registry.for_api("zeta")).await;
        let _ = registry.for_api("alpha"); // route built, no traffic yet

        let snap = registry.snapshot();
        let ids: Vec<_> = snap.iter().map(|s| s.api_id.as_str()).collect();
        assert_eq!(ids, ["alpha", "zeta"]);
        assert_eq!(snap[1].requests, 2, "counters survived the rebuild");
        assert_eq!(snap[0].requests, 0);
    }
}
