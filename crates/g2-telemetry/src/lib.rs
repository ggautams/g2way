//! Telemetry for g2way.
//!
//! Two concerns live here:
//!
//! - **Log/trace subscriber initialization** for the gateway binary:
//!   [`init_telemetry`] installs the global `tracing` subscriber (JSON or
//!   pretty logs) and, when an [`OtlpConfig`] is given, an OpenTelemetry
//!   bridge layer that exports every per-request span (created by
//!   `g2-middleware`'s `TraceLayer`) over OTLP.
//! - **OTLP export plumbing** ([`otlp`], [`metrics`]): the span and metric
//!   exporters speak OTLP over HTTP/protobuf (`{endpoint}/v1/traces` and
//!   `/v1/metrics`, default collector port 4318) and batch on dedicated
//!   background threads, so they need no handle to the tokio runtime and
//!   work from process start to after-runtime shutdown. The metrics side
//!   can additionally (or instead) encode into a Prometheus registry,
//!   rendered on demand through [`PrometheusHandle`] — the admin API's
//!   `GET /metrics` endpoint.
//!
//! Remaining milestone M5 work: per-request analytics records
//! behind an `AnalyticsSink` trait. See `ROADMAP.md` at the workspace root.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

pub mod metrics;
pub mod otlp;

pub use metrics::PrometheusHandle;
pub use otlp::OtlpConfig;

/// Output format for gateway logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line — the k8s/Datadog-agent friendly default.
    Json,
    /// Human-readable output for local development.
    Pretty,
}

/// Error returned when parsing a [`LogFormat`] from a string fails.
#[derive(Debug, thiserror::Error)]
#[error("unknown log format `{0}`; expected `json` or `pretty`")]
pub struct ParseLogFormatError(String);

impl FromStr for LogFormat {
    type Err = ParseLogFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "pretty" => Ok(Self::Pretty),
            other => Err(ParseLogFormatError(other.to_owned())),
        }
    }
}

/// Error initializing telemetry (building an exporter failed).
#[derive(Debug, thiserror::Error)]
pub enum InitTelemetryError {
    /// The OTLP span exporter could not be built.
    #[error("failed to initialize OTLP trace export: {0}")]
    OtlpTraces(#[from] opentelemetry_otlp::ExporterBuildError),
    /// The OTLP metric exporter could not be built.
    #[error("failed to initialize OTLP metric export: {0}")]
    OtlpMetrics(opentelemetry_otlp::ExporterBuildError),
    /// The Prometheus exporter could not be built.
    #[error("failed to initialize Prometheus metric export: {0}")]
    Prometheus(String),
}

/// Handle flushing buffered spans and metrics at process exit, and carrying
/// the Prometheus render handle when the pull side is enabled.
///
/// Hold it for the life of the process and call [`shutdown`](Self::shutdown)
/// as the last thing before exiting; dropping it without calling `shutdown`
/// still flushes (the providers shut down on their last drop) but swallows
/// any export error.
#[derive(Debug)]
#[must_use = "dropping the guard early stops telemetry export"]
pub struct TelemetryGuard {
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    meter_provider: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
    prometheus: Option<PrometheusHandle>,
}

impl TelemetryGuard {
    /// The Prometheus render handle, when `prometheus` was enabled at init.
    #[must_use]
    pub fn prometheus(&self) -> Option<PrometheusHandle> {
        self.prometheus.clone()
    }

    /// Flushes buffered telemetry and shuts the exporters down, logging
    /// (not returning) any failure — at shutdown there is nothing left to
    /// do about it.
    pub fn shutdown(self) {
        if let Some(provider) = self.tracer_provider {
            if let Err(err) = provider.shutdown() {
                tracing::warn!(error = %err, "OTLP trace exporter shutdown failed");
            }
        }
        if let Some(provider) = self.meter_provider {
            if let Err(err) = provider.shutdown() {
                tracing::warn!(error = %err, "metric exporter shutdown failed");
            }
        }
    }
}

/// Initializes global telemetry for the gateway process: the `tracing`
/// subscriber (stdout logs in the given `format`, plus OTLP span export
/// when `otlp` is configured) and the global meter provider (OTLP metric
/// export when `otlp` is configured, a Prometheus registry when
/// `prometheus` is `true`, nothing when neither).
///
/// The log level is taken from the `RUST_LOG` environment variable and
/// defaults to `info` when unset; the filter also gates span export, so
/// per-request spans (info level) stop being exported under `RUST_LOG=warn`.
/// Metrics are not filtered — they flow whenever an export side is enabled.
/// Call this exactly once, at process start; calling it twice panics (a
/// programming error, not a runtime condition).
///
/// # Errors
///
/// Returns [`InitTelemetryError`] when an exporter cannot be built from
/// `otlp` (e.g. a malformed endpoint URL).
pub fn init_telemetry(
    format: LogFormat,
    otlp: Option<&OtlpConfig>,
    prometheus: bool,
) -> Result<TelemetryGuard, InitTelemetryError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let (otel_layer, tracer_provider) = match otlp {
        Some(cfg) => {
            use opentelemetry::trace::TracerProvider as _;
            let provider = otlp::build_tracer_provider(cfg)?;
            let tracer = provider.tracer("g2way");
            let layer = tracing_opentelemetry::layer().with_tracer(tracer);
            (Some(layer), Some(provider))
        }
        None => (None, None),
    };

    let (meter_provider, prometheus) = match metrics::build_meter_provider(otlp, prometheus)? {
        Some((provider, handle)) => {
            // Installed globally so `g2_middleware::HttpMetrics::new()`
            // (called after init) binds its instruments to it.
            opentelemetry::global::set_meter_provider(provider.clone());
            (Some(provider), handle)
        }
        None => (None, None),
    };

    let registry = tracing_subscriber::registry().with(filter).with(otel_layer);
    match format {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true),
            )
            .init(),
        LogFormat::Pretty => registry.with(tracing_subscriber::fmt::layer()).init(),
    }

    Ok(TelemetryGuard {
        tracer_provider,
        meter_provider,
        prometheus,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_format_parses_case_insensitively() {
        assert_eq!("json".parse::<LogFormat>().expect("json"), LogFormat::Json);
        assert_eq!("JSON".parse::<LogFormat>().expect("JSON"), LogFormat::Json);
        assert_eq!(
            "Pretty".parse::<LogFormat>().expect("Pretty"),
            LogFormat::Pretty
        );
    }

    #[test]
    fn unknown_log_format_is_an_error() {
        let err = "xml".parse::<LogFormat>().unwrap_err();
        assert!(err.to_string().contains("xml"));
    }
}
