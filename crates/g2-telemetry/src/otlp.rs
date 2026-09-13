//! OTLP span export: exporter and tracer-provider construction.
//!
//! Transport is OTLP over **HTTP/protobuf** (`POST {endpoint}/v1/traces`,
//! default collector port 4318) with a blocking HTTP client driven from the
//! SDK's dedicated batch-export thread. That combination deliberately avoids
//! any dependency on the tokio runtime: the provider can be built before the
//! runtime starts and flushed after it stops, and a slow collector never
//! occupies a runtime worker. gRPC (tonic) transport was considered and
//! rejected for exactly that runtime coupling.

use opentelemetry::KeyValue;
use opentelemetry_otlp::{ExporterBuildError, Protocol, WithExportConfig as _};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;

/// Settings for OTLP trace export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpConfig {
    /// Base endpoint of the OTLP/HTTP collector, e.g.
    /// `http://otel-collector:4318`. The standard `/v1/traces` signal path
    /// is appended automatically (unless already present).
    pub endpoint: String,
}

/// The full `/v1/traces` URL for a configured base endpoint.
///
/// Idempotent: an endpoint already carrying the signal path (with or
/// without a trailing slash) is left alone, so both the base-URL and
/// full-URL conventions work.
#[must_use]
pub fn traces_endpoint(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/v1/traces") {
        trimmed.to_owned()
    } else {
        format!("{trimmed}/v1/traces")
    }
}

/// The OTel resource identifying this gateway process: service name and
/// version, plus `host.name` from `$HOSTNAME` when set (the pod name on
/// k8s — the same identity the admin API's `/g2/node` reports).
pub(crate) fn resource() -> Resource {
    let mut attrs = vec![KeyValue::new("service.version", env!("CARGO_PKG_VERSION"))];
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        if !hostname.is_empty() {
            attrs.push(KeyValue::new("host.name", hostname));
        }
    }
    Resource::builder()
        .with_service_name("g2way")
        .with_attributes(attrs)
        .build()
}

/// Builds a tracer provider exporting batched spans to `cfg.endpoint`.
///
/// # Errors
///
/// Returns [`ExporterBuildError`] when the exporter cannot be constructed
/// (e.g. the endpoint is not a valid URL).
pub fn build_tracer_provider(cfg: &OtlpConfig) -> Result<SdkTracerProvider, ExporterBuildError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(traces_endpoint(&cfg.endpoint))
        .build()?;
    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource())
        .build())
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::mpsc;

    use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};

    use super::*;

    #[test]
    fn traces_endpoint_appends_signal_path_idempotently() {
        assert_eq!(
            traces_endpoint("http://collector:4318"),
            "http://collector:4318/v1/traces"
        );
        assert_eq!(
            traces_endpoint("http://collector:4318/"),
            "http://collector:4318/v1/traces"
        );
        assert_eq!(
            traces_endpoint("http://collector:4318/v1/traces"),
            "http://collector:4318/v1/traces"
        );
        assert_eq!(
            traces_endpoint("http://collector:4318/v1/traces/"),
            "http://collector:4318/v1/traces"
        );
    }

    /// A minimal one-shot OTLP/HTTP collector: accepts one request, sends
    /// back the request line + headers, and answers 200.
    fn fake_collector() -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind collector");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream);
            let mut head = String::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("read header line");
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().expect("content-length");
                }
                let done = line == "\r\n" || line == "\n";
                head.push_str(&line);
                if done {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).expect("read body");
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .expect("write response");
            let _ = tx.send(head);
        });
        (endpoint, rx)
    }

    #[test]
    fn exports_spans_to_the_collector_over_otlp_http() {
        let (endpoint, rx) = fake_collector();
        let provider = build_tracer_provider(&OtlpConfig { endpoint }).expect("provider");

        let tracer = provider.tracer("test");
        let mut span = tracer.start("test-span");
        span.end();
        provider.force_flush().expect("flush");

        let head = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("collector saw a request");
        assert!(head.starts_with("POST /v1/traces"), "request head:\n{head}");
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/x-protobuf"),
            "request head:\n{head}"
        );
        provider.shutdown().expect("shutdown");
    }
}
