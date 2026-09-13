//! OTLP metric export and the Prometheus pull-side plumbing.
//!
//! One [`SdkMeterProvider`] carries up to two readers over the same
//! instruments (created by `g2-middleware`'s `MetricsLayer`):
//!
//! - a **periodic OTLP push** reader (`POST {endpoint}/v1/metrics`,
//!   HTTP/protobuf) sharing the trace exporter's endpoint and its
//!   no-tokio-dependency design (see [`crate::otlp`]), and
//! - a **Prometheus pull** reader encoding into a [`prometheus::Registry`],
//!   rendered on demand by [`PrometheusHandle::render`] — the admin API
//!   serves it at `GET /metrics`.
//!
//! With neither side enabled no provider is built at all and the global
//! meter stays the no-op default, so instruments cost nothing.

use opentelemetry_otlp::{ExporterBuildError, Protocol, WithExportConfig as _};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use prometheus::{Encoder as _, Registry, TextEncoder};

use crate::otlp::{resource, OtlpConfig};
use crate::InitTelemetryError;

/// The full `/v1/metrics` URL for a configured base endpoint.
///
/// Idempotent like [`crate::otlp::traces_endpoint`]: an endpoint already
/// carrying the signal path is left alone.
#[must_use]
pub fn metrics_endpoint(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/v1/metrics") {
        trimmed.to_owned()
    } else {
        format!("{trimmed}/v1/metrics")
    }
}

/// Cheap-clone handle rendering the gateway's metrics in the Prometheus
/// text exposition format.
///
/// Obtained from [`crate::TelemetryGuard::prometheus`] and handed to the
/// admin API, which serves the rendered text at `GET /metrics`.
#[derive(Debug, Clone)]
pub struct PrometheusHandle {
    registry: Registry,
}

impl PrometheusHandle {
    /// Renders every metric family in the registry as Prometheus text.
    ///
    /// Encoding into an in-memory buffer cannot realistically fail; if it
    /// ever does (a metric family violating the exposition format), the
    /// error is logged and an empty document returned — a scrape must
    /// never take the admin API down.
    #[must_use]
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        if let Err(err) = TextEncoder::new().encode(&self.registry.gather(), &mut buf) {
            tracing::error!(error = %err, "Prometheus metrics encoding failed");
            return String::new();
        }
        String::from_utf8(buf).unwrap_or_else(|err| {
            tracing::error!(error = %err, "Prometheus metrics were not UTF-8");
            String::new()
        })
    }
}

/// Builds the meter provider for the enabled export sides: OTLP push when
/// `otlp` is configured, Prometheus pull when `prometheus` is `true`.
///
/// Returns `None` (and installs nothing) when both are off. The gateway
/// binary reaches this through [`crate::init_telemetry`], which also
/// installs the provider globally; it is public for embedders and tests
/// managing their own provider.
///
/// # Errors
///
/// Returns [`InitTelemetryError`] when an exporter cannot be constructed
/// (e.g. a malformed endpoint URL).
pub fn build_meter_provider(
    otlp: Option<&OtlpConfig>,
    prometheus: bool,
) -> Result<Option<(SdkMeterProvider, Option<PrometheusHandle>)>, InitTelemetryError> {
    if otlp.is_none() && !prometheus {
        return Ok(None);
    }
    let mut builder = SdkMeterProvider::builder().with_resource(resource());

    if let Some(cfg) = otlp {
        let exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(metrics_endpoint(&cfg.endpoint))
            .build()
            .map_err(otlp_metric_error)?;
        builder = builder.with_reader(PeriodicReader::builder(exporter).build());
    }

    let handle = if prometheus {
        let registry = Registry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .build()
            .map_err(|e| InitTelemetryError::Prometheus(e.to_string()))?;
        builder = builder.with_reader(exporter);
        Some(PrometheusHandle { registry })
    } else {
        None
    };

    Ok(Some((builder.build(), handle)))
}

fn otlp_metric_error(err: ExporterBuildError) -> InitTelemetryError {
    InitTelemetryError::OtlpMetrics(err)
}

#[cfg(test)]
mod tests {
    use opentelemetry::metrics::MeterProvider as _;

    use super::*;

    #[test]
    fn metrics_endpoint_appends_signal_path_idempotently() {
        assert_eq!(
            metrics_endpoint("http://collector:4318"),
            "http://collector:4318/v1/metrics"
        );
        assert_eq!(
            metrics_endpoint("http://collector:4318/v1/metrics/"),
            "http://collector:4318/v1/metrics"
        );
    }

    #[test]
    fn disabled_metrics_build_no_provider() {
        assert!(build_meter_provider(None, false).expect("build").is_none());
    }

    #[test]
    fn prometheus_handle_renders_recorded_instruments() {
        let (provider, handle) = build_meter_provider(None, true)
            .expect("build")
            .expect("provider");
        let handle = handle.expect("prometheus handle");

        let histogram = provider
            .meter("g2way")
            .f64_histogram("http.server.request.duration")
            .with_unit("s")
            .build();
        histogram.record(
            0.042,
            &[opentelemetry::KeyValue::new("http.route", "/users")],
        );

        let text = handle.render();
        assert!(
            text.contains("http_server_request_duration_seconds"),
            "rendered:\n{text}"
        );
        assert!(text.contains("http_route=\"/users\""), "rendered:\n{text}");
        provider.shutdown().expect("shutdown");
    }
}
