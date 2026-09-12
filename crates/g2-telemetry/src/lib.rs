//! Telemetry for g2way.
//!
//! Milestone M1 scope: structured logging initialization for the gateway
//! binary. Milestone M5 adds OTLP trace/metric export, a Prometheus
//! `/metrics` endpoint, and per-request analytics records behind an
//! `AnalyticsSink` trait. See `ROADMAP.md` at the workspace root.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

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

/// Initializes the global `tracing` subscriber for the gateway process.
///
/// The log level is taken from the `RUST_LOG` environment variable and
/// defaults to `info` when unset. Call this exactly once, at process start;
/// calling it twice panics (a programming error, not a runtime condition).
pub fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_current_span(true)
            .init(),
        LogFormat::Pretty => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
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
