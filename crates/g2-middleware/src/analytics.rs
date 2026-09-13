//! Per-request analytics record production.
//!
//! [`AnalyticsLayer`] sits above auth in an API's chain (rejections are
//! traffic too) and builds one [`AnalyticsRecord`] per response, handing it
//! to an [`AnalyticsHandle`] — a bounded channel into the process-wide
//! analytics worker (`g2-telemetry`), which batches records into the
//! configured sink. The hand-off is a `try_send`: when the worker falls
//! behind, records are **dropped and counted**, never buffered unboundedly
//! and never blocking the request (ADR-0001 hot-path rules).
//!
//! Fields only inner layers know — the authenticated session, the upstream
//! round-trip time — travel outward in **response** extensions
//! ([`SessionContext`] stamped by the auth layer, [`UpstreamLatency`] by
//! the forwarding service), because a layer above auth never sees request
//! extensions stamped below it.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use g2_core::AnalyticsRecord;
use http::{HeaderMap, Request, Response};
use tokio::sync::mpsc;
use tower::{Layer, Service};

use crate::context::{ClientAddr, RequestContext, SessionContext, UpstreamLatency};
use crate::ProxyBody;

/// Producer half of the analytics channel, shared by every route.
///
/// Cheap to clone (all clones feed the same worker). [`record`](Self::record)
/// never blocks: a full or closed channel drops the record and bumps
/// [`dropped`](Self::dropped).
#[derive(Debug, Clone)]
pub struct AnalyticsHandle {
    tx: mpsc::Sender<AnalyticsRecord>,
    dropped: Arc<AtomicU64>,
}

impl AnalyticsHandle {
    /// Creates the bounded analytics channel: the handle for producers and
    /// the receiver for the worker draining into a sink.
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<AnalyticsRecord>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Queues `record` for the worker, dropping it (and counting the drop)
    /// when the channel is full or the worker is gone.
    pub fn record(&self, record: AnalyticsRecord) {
        if let Err(err) = self.tx.try_send(record) {
            let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::debug!(total_dropped = total, error = %err, "analytics record dropped");
        }
    }

    /// Number of records dropped so far because the worker fell behind.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Parses a numeric `Content-Length` header, if present.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Milliseconds since the Unix epoch, saturating.
fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Tower layer producing one [`AnalyticsRecord`] per response of one API.
#[derive(Debug, Clone)]
pub struct AnalyticsLayer {
    handle: AnalyticsHandle,
    ctx: RequestContext,
}

impl AnalyticsLayer {
    /// Builds the layer for the API identified by `ctx`, feeding `handle`.
    #[must_use]
    pub fn new(handle: AnalyticsHandle, ctx: RequestContext) -> Self {
        Self { handle, ctx }
    }
}

impl<S> Layer<S> for AnalyticsLayer {
    type Service = Analytics<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Analytics {
            inner,
            handle: self.handle.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

/// The [`Service`] produced by [`AnalyticsLayer`].
#[derive(Debug, Clone)]
pub struct Analytics<S> {
    inner: S,
    handle: AnalyticsHandle,
    ctx: RequestContext,
}

impl<S> Service<Request<ProxyBody>> for Analytics<S>
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
        let handle = self.handle.clone();
        let ctx = self.ctx.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        // Request-side facts, captured before the request moves on. These
        // allocations exist only when an analytics sink is configured; the
        // record itself is inherently per-request data.
        let started = Instant::now();
        let timestamp_unix_ms = unix_ms_now();
        let method = req.method().to_string();
        let path = req.uri().path().to_owned();
        let client_ip = req
            .extensions()
            .get::<ClientAddr>()
            .map(|addr| addr.0.ip().to_string());
        let user_agent = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let request_content_length = content_length(req.headers());

        Box::pin(async move {
            let resp = inner.call(req).await?;
            let session = resp.extensions().get::<SessionContext>();
            let record = AnalyticsRecord {
                timestamp_unix_ms,
                api_id: ctx.api_id().to_owned(),
                org_id: ctx.org_id().to_owned(),
                method,
                path,
                status: resp.status().as_u16(),
                latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                upstream_latency_ms: resp
                    .extensions()
                    .get::<UpstreamLatency>()
                    .map(|lat| u64::try_from(lat.0.as_millis()).unwrap_or(u64::MAX)),
                key_hash: session.map(|s| s.key_hash().to_owned()),
                key_alias: session.and_then(|s| s.session().alias.clone()),
                client_ip,
                user_agent,
                request_content_length,
                response_content_length: content_length(resp.headers()),
            };
            handle.record(record);
            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderValue, StatusCode};
    use http_body_util::Full;
    use tower::ServiceExt;

    use super::*;

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    fn session_ctx() -> SessionContext {
        let session: g2_core::KeySession =
            serde_json::from_str(r#"{"org_id":"acme","alias":"mobile-app"}"#).expect("session");
        SessionContext::new(session, "hash1234")
    }

    /// Inner service standing in for auth + forward: stamps the response
    /// extensions those layers stamp.
    async fn stamped_inner(_req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let mut resp = Response::new(body());
        *resp.status_mut() = StatusCode::CREATED;
        resp.headers_mut()
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("7"));
        resp.extensions_mut().insert(session_ctx());
        resp.extensions_mut()
            .insert(UpstreamLatency(Duration::from_millis(9)));
        Ok(resp)
    }

    #[tokio::test]
    async fn builds_a_full_record_from_request_and_response() {
        let (handle, mut rx) = AnalyticsHandle::channel(8);
        let layer = AnalyticsLayer::new(handle, RequestContext::new("users-api", "acme"));
        let svc = layer.layer(tower::service_fn(stamped_inner));

        let addr: SocketAddr = "10.1.2.3:5555".parse().expect("addr");
        let mut req = Request::builder()
            .method("POST")
            .uri("/users/42?token=secret")
            .header(http::header::USER_AGENT, "curl/8")
            .header(http::header::CONTENT_LENGTH, "11")
            .body(body())
            .expect("request");
        req.extensions_mut().insert(ClientAddr(addr));

        svc.oneshot(req).await.expect("infallible");
        let record = rx.try_recv().expect("one record queued");

        assert_eq!(record.api_id, "users-api");
        assert_eq!(record.org_id, "acme");
        assert_eq!(record.method, "POST");
        assert_eq!(record.path, "/users/42", "query string must not leak");
        assert_eq!(record.status, 201);
        assert_eq!(record.upstream_latency_ms, Some(9));
        assert_eq!(record.key_hash.as_deref(), Some("hash1234"));
        assert_eq!(record.key_alias.as_deref(), Some("mobile-app"));
        assert_eq!(record.client_ip.as_deref(), Some("10.1.2.3"));
        assert_eq!(record.user_agent.as_deref(), Some("curl/8"));
        assert_eq!(record.request_content_length, Some(11));
        assert_eq!(record.response_content_length, Some(7));
        assert!(record.timestamp_unix_ms > 0);
    }

    #[tokio::test]
    async fn requests_without_session_or_upstream_yield_bare_records() {
        let (handle, mut rx) = AnalyticsHandle::channel(8);
        let layer = AnalyticsLayer::new(handle, RequestContext::new("a", "o"));
        let svc = layer.layer(tower::service_fn(|_req: Request<ProxyBody>| async {
            // A 403 rejected inside the gateway: no session, no upstream.
            let mut resp = Response::new(body());
            *resp.status_mut() = StatusCode::FORBIDDEN;
            Ok::<_, Infallible>(resp)
        }));

        svc.oneshot(Request::new(body())).await.expect("infallible");
        let record = rx.try_recv().expect("rejections are recorded too");
        assert_eq!(record.status, 403);
        assert_eq!(record.upstream_latency_ms, None);
        assert_eq!(record.key_hash, None);
        assert_eq!(record.client_ip, None);
    }

    #[tokio::test]
    async fn full_channel_drops_and_counts_instead_of_blocking() {
        let (handle, mut rx) = AnalyticsHandle::channel(1);
        let layer = AnalyticsLayer::new(handle.clone(), RequestContext::new("a", "o"));
        let ok = tower::service_fn(|_req: Request<ProxyBody>| async {
            Ok::<_, Infallible>(Response::new(body()))
        });

        for _ in 0..3 {
            layer
                .clone()
                .layer(ok)
                .oneshot(Request::new(body()))
                .await
                .expect("infallible");
        }
        assert_eq!(handle.dropped(), 2, "capacity 1 admits exactly one record");
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err(), "the dropped records never arrive");
    }
}
