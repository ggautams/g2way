//! Per-request OpenTelemetry metrics.
//!
//! [`MetricsLayer`] sits just below the trace layer in an API's chain and
//! records one [`HttpMetrics`] histogram sample per response:
//! `http.server.request.duration` (seconds, OTel HTTP semantic conventions),
//! attributed by route, status code, and the gateway's API/org identity.
//! One histogram carries everything a dashboard needs — request rate
//! (sample count), error rate (status-code attribute), and latency
//! distribution.
//!
//! Instruments are created once per process ([`HttpMetrics::new`], after the
//! global meter provider is installed) and shared by every route across
//! reloads; the per-API attribute set is precomputed at route-build time
//! (ADR-0001 hot-path rules), leaving only the status-code attribute and the
//! histogram record itself per request. Like spans, samples exist only for
//! routed requests: health endpoints and 404s never enter a chain.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use http::{Request, Response};
use opentelemetry::metrics::{Histogram, Meter};
use opentelemetry::{global, KeyValue, Value};
use tower::{Layer, Service};

use crate::context::RequestContext;
use crate::ProxyBody;

/// Explicit histogram bucket boundaries (seconds) recommended by the OTel
/// HTTP semantic conventions for `http.server.request.duration`. The SDK's
/// defaults are tuned for milliseconds and useless for a value in seconds.
const DURATION_BOUNDARIES_SECS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

/// The gateway's request-level instruments, created once per process and
/// shared by every route.
#[derive(Debug, Clone)]
pub struct HttpMetrics {
    request_duration: Histogram<f64>,
}

impl HttpMetrics {
    /// Creates the instruments on the **global** meter provider.
    ///
    /// Call this after the provider is installed (the binary does so in
    /// telemetry init); instruments created earlier bind to the no-op
    /// default provider and silently record nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::with_meter(&global::meter("g2way"))
    }

    /// Creates the instruments on an explicit meter (used by tests, and by
    /// embedders managing their own provider).
    #[must_use]
    pub fn with_meter(meter: &Meter) -> Self {
        let request_duration = meter
            .f64_histogram("http.server.request.duration")
            .with_unit("s")
            .with_description("Duration of proxied HTTP requests, gateway overhead included.")
            .with_boundaries(DURATION_BOUNDARIES_SECS.to_vec())
            .build();
        Self { request_duration }
    }
}

impl Default for HttpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Tower layer recording one duration sample per response of one API.
#[derive(Debug, Clone)]
pub struct MetricsLayer {
    metrics: Arc<HttpMetrics>,
    base_attrs: Arc<[KeyValue]>,
}

impl MetricsLayer {
    /// Builds the layer for the API identified by `ctx`; `route` should be
    /// the API's listen path (the low-cardinality `http.route` attribute,
    /// mirroring the trace layer's span name).
    #[must_use]
    pub fn new(metrics: Arc<HttpMetrics>, ctx: &RequestContext, route: &str) -> Self {
        // Arc-backed values so per-request clones are refcount bumps, not
        // string copies.
        let arc_val = |s: &str| Value::from(Arc::<str>::from(s));
        let base_attrs: Arc<[KeyValue]> = Arc::from([
            KeyValue::new("http.route", arc_val(route)),
            KeyValue::new("g2.api_id", arc_val(ctx.api_id())),
            KeyValue::new("g2.org_id", arc_val(ctx.org_id())),
        ]);
        Self {
            metrics,
            base_attrs,
        }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = Metrics<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Metrics {
            inner,
            metrics: Arc::clone(&self.metrics),
            base_attrs: Arc::clone(&self.base_attrs),
        }
    }
}

/// The [`Service`] produced by [`MetricsLayer`].
#[derive(Debug, Clone)]
pub struct Metrics<S> {
    inner: S,
    metrics: Arc<HttpMetrics>,
    base_attrs: Arc<[KeyValue]>,
}

impl<S> Service<Request<ProxyBody>> for Metrics<S>
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
        let metrics = Arc::clone(&self.metrics);
        let base_attrs = Arc::clone(&self.base_attrs);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let start = Instant::now();
            let resp = inner.call(req).await?;
            let mut attrs = Vec::with_capacity(base_attrs.len() + 1);
            attrs.extend_from_slice(&base_attrs);
            attrs.push(KeyValue::new(
                "http.response.status_code",
                i64::from(resp.status().as_u16()),
            ));
            metrics
                .request_duration
                .record(start.elapsed().as_secs_f64(), &attrs);
            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::StatusCode;
    use http_body_util::Full;
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::in_memory_exporter::InMemoryMetricExporter;
    use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
    use tower::ServiceExt;

    use super::*;

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    fn provider() -> (SdkMeterProvider, InMemoryMetricExporter) {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        (
            SdkMeterProvider::builder().with_reader(reader).build(),
            exporter,
        )
    }

    async fn respond(status: StatusCode, layer: &MetricsLayer) {
        let svc = layer.clone().layer(tower::service_fn(
            move |_req: Request<ProxyBody>| async move {
                let mut resp = Response::new(body());
                *resp.status_mut() = status;
                Ok::<_, Infallible>(resp)
            },
        ));
        svc.oneshot(Request::new(body())).await.expect("infallible");
    }

    #[tokio::test]
    async fn records_duration_samples_with_route_and_status_attributes() {
        let (provider, exporter) = provider();
        let metrics = Arc::new(HttpMetrics::with_meter(&provider.meter("g2way")));
        let layer = MetricsLayer::new(metrics, &RequestContext::new("users-api", "acme"), "/users");
        respond(StatusCode::OK, &layer).await;
        respond(StatusCode::OK, &layer).await;
        respond(StatusCode::BAD_GATEWAY, &layer).await;
        provider.force_flush().expect("flush");

        let finished = exporter.get_finished_metrics().expect("metrics");
        let metric = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .find(|m| m.name() == "http.server.request.duration")
            .expect("histogram exported");
        assert_eq!(metric.unit(), "s");
        let AggregatedMetrics::F64(MetricData::Histogram(hist)) = metric.data() else {
            panic!("expected an f64 histogram");
        };

        // One data point per distinct attribute set: (…, 200) and (…, 502).
        let mut by_status = std::collections::HashMap::new();
        for point in hist.data_points() {
            let attr = |key: &str| {
                point
                    .attributes()
                    .find(|kv| kv.key.as_str() == key)
                    .map(|kv| kv.value.to_string())
            };
            assert_eq!(attr("http.route").as_deref(), Some("/users"));
            assert_eq!(attr("g2.api_id").as_deref(), Some("users-api"));
            assert_eq!(attr("g2.org_id").as_deref(), Some("acme"));
            assert!(point.sum() >= 0.0, "durations are non-negative");
            by_status.insert(
                attr("http.response.status_code").expect("status attr"),
                point.count(),
            );
        }
        assert_eq!(by_status.get("200"), Some(&2), "points: {by_status:?}");
        assert_eq!(by_status.get("502"), Some(&1), "points: {by_status:?}");
    }

    #[tokio::test]
    async fn instruments_on_the_noop_global_provider_record_nothing_and_do_not_panic() {
        // No global provider installed in this test process: the layer must
        // still pass requests through untouched.
        let layer = MetricsLayer::new(
            Arc::new(HttpMetrics::new()),
            &RequestContext::new("a", "o"),
            "/",
        );
        respond(StatusCode::OK, &layer).await;
    }
}
