//! Analytics record delivery: the [`AnalyticsSink`] trait, its sinks, and
//! the batching worker.
//!
//! `g2-middleware`'s analytics layer produces one
//! [`AnalyticsRecord`] per proxied request and
//! pushes it into a bounded channel; [`run`] is the process-wide worker
//! draining that channel, batching records, and handing each batch to the
//! configured sink (ADR-0001 keeps room for a native pump by
//! making the sink a trait):
//!
//! - [`StdoutJsonSink`] — one JSON object per line on stdout, interleaving
//!   cleanly with the gateway's line-delimited JSON logs.
//! - [`RedisListSink`] — records appended to a capped per-org Redis list
//!   (`g2:{org}:analytics:records`) for an external pump to drain with
//!   `Storage::list_drain`.
//! - [`OtlpLogsSink`] — records exported as OTLP log records
//!   (`POST {endpoint}/v1/logs`), sharing the trace/metric exporters'
//!   HTTP/protobuf no-tokio-dependency design (see [`crate::otlp`]).
//!
//! A sink failure drops that batch (loudly logged): analytics must never
//! apply backpressure to the proxy path.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use g2_core::analytics::analytics_records_key;
use g2_core::AnalyticsRecord;
use g2_storage::SharedStorage;
use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity};
use opentelemetry_otlp::{ExporterBuildError, Protocol, WithExportConfig as _};
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider};
use tokio::sync::{mpsc, watch};

use crate::otlp::{resource, OtlpConfig};

/// Records per batch handed to the sink; also the flush trigger when the
/// buffer fills between ticks.
const BATCH_SIZE: usize = 512;

/// How often a partially filled buffer is flushed to the sink.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// Error returned by a sink that failed to deliver a batch.
#[derive(Debug, thiserror::Error)]
#[error("analytics sink failed: {0}")]
pub struct AnalyticsSinkError(pub String);

/// A destination for per-request analytics records.
///
/// Implementations receive whole batches (the worker amortizes per-delivery
/// overhead) and must not block indefinitely — a failed delivery should
/// error out so the worker can drop the batch and keep going.
#[async_trait::async_trait]
pub trait AnalyticsSink: Send + Sync + 'static {
    /// The sink's name, for logs.
    fn name(&self) -> &'static str;

    /// Delivers one batch of records.
    ///
    /// # Errors
    ///
    /// Returns [`AnalyticsSinkError`] when the batch could not be
    /// delivered; the caller drops the batch.
    async fn emit(&self, records: &[AnalyticsRecord]) -> Result<(), AnalyticsSinkError>;

    /// Flushes anything the sink buffers internally, at worker shutdown.
    /// The default does nothing.
    fn shutdown(&self) {}
}

/// Sink writing one JSON record per line to stdout.
///
/// The gateway's JSON logs are line-delimited JSON on stdout too, so a log
/// shipper ingesting the stream can tell records apart by shape (or by the
/// `timestamp_unix_ms`/`api_id` fields unique to analytics records).
#[derive(Debug, Clone, Copy, Default)]
pub struct StdoutJsonSink;

impl StdoutJsonSink {
    /// Creates the sink.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AnalyticsSink for StdoutJsonSink {
    fn name(&self) -> &'static str {
        "stdout"
    }

    async fn emit(&self, records: &[AnalyticsRecord]) -> Result<(), AnalyticsSinkError> {
        use std::io::Write as _;

        // One buffer, one write: keeps lines from different writers from
        // interleaving mid-record.
        let mut buf = Vec::with_capacity(records.len() * 256);
        for record in records {
            serde_json::to_writer(&mut buf, record)
                .map_err(|e| AnalyticsSinkError(e.to_string()))?;
            buf.push(b'\n');
        }
        std::io::stdout()
            .lock()
            .write_all(&buf)
            .map_err(|e| AnalyticsSinkError(e.to_string()))
    }
}

/// Sink appending records to a capped per-org Redis list.
///
/// Records land (in arrival order) at `g2:{org}:analytics:records`, ready
/// for an external pump to [`list_drain`](g2_storage::Storage::list_drain).
/// The list is capped at [`max_records`](Self::with_max_records) — with no
/// pump draining it, the **oldest** records fall off instead of Redis
/// filling up.
#[derive(Clone)]
pub struct RedisListSink {
    storage: SharedStorage,
    max_records: u64,
}

impl std::fmt::Debug for RedisListSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisListSink")
            .field("max_records", &self.max_records)
            .finish_non_exhaustive()
    }
}

impl RedisListSink {
    /// Per-org list cap applied by [`new`](Self::new).
    pub const DEFAULT_MAX_RECORDS: u64 = 100_000;

    /// Creates the sink over `storage` with the default list cap.
    #[must_use]
    pub fn new(storage: SharedStorage) -> Self {
        Self {
            storage,
            max_records: Self::DEFAULT_MAX_RECORDS,
        }
    }

    /// Overrides the per-org list cap.
    #[must_use]
    pub fn with_max_records(mut self, max_records: u64) -> Self {
        self.max_records = max_records;
        self
    }
}

#[async_trait::async_trait]
impl AnalyticsSink for RedisListSink {
    fn name(&self) -> &'static str {
        "redis"
    }

    async fn emit(&self, records: &[AnalyticsRecord]) -> Result<(), AnalyticsSinkError> {
        // One list per org (multi-org readiness); a batch is almost always
        // single-org today, so group instead of one round trip per record.
        let mut by_org: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
        for record in records {
            let json =
                serde_json::to_string(record).map_err(|e| AnalyticsSinkError(e.to_string()))?;
            by_org.entry(&record.org_id).or_default().push(json);
        }
        for (org_id, values) in by_org {
            self.storage
                .list_append(
                    &analytics_records_key(org_id),
                    &values,
                    Some(self.max_records),
                )
                .await
                .map_err(|e| AnalyticsSinkError(e.to_string()))?;
        }
        Ok(())
    }
}

/// The full `/v1/logs` URL for a configured base endpoint.
///
/// Idempotent like [`crate::otlp::traces_endpoint`]: an endpoint already
/// carrying the signal path is left alone.
#[must_use]
pub fn logs_endpoint(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/v1/logs") {
        trimmed.to_owned()
    } else {
        format!("{trimmed}/v1/logs")
    }
}

/// Sink exporting each record as one OTLP log record.
///
/// The log record's body is the record's JSON serialization (self-contained
/// for any backend), with the identity fields every backend indexes —
/// `g2.api_id`, `g2.org_id`, `http.response.status_code` — duplicated as
/// attributes. The exporter batches on its own thread (same design as span
/// and metric export); [`AnalyticsSink::shutdown`] flushes it.
#[derive(Debug)]
pub struct OtlpLogsSink {
    provider: SdkLoggerProvider,
    logger: SdkLogger,
}

impl OtlpLogsSink {
    /// Builds the sink exporting to `{cfg.endpoint}/v1/logs`.
    ///
    /// # Errors
    ///
    /// Returns [`ExporterBuildError`] when the exporter cannot be
    /// constructed (e.g. the endpoint is not a valid URL).
    pub fn new(cfg: &OtlpConfig) -> Result<Self, ExporterBuildError> {
        let exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(logs_endpoint(&cfg.endpoint))
            .build()?;
        let provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource())
            .build();
        let logger = provider.logger("g2way");
        Ok(Self { provider, logger })
    }
}

#[async_trait::async_trait]
impl AnalyticsSink for OtlpLogsSink {
    fn name(&self) -> &'static str {
        "otlp_logs"
    }

    async fn emit(&self, records: &[AnalyticsRecord]) -> Result<(), AnalyticsSinkError> {
        for record in records {
            let json =
                serde_json::to_string(record).map_err(|e| AnalyticsSinkError(e.to_string()))?;
            let mut log = self.logger.create_log_record();
            log.set_event_name("g2.analytics");
            log.set_severity_number(Severity::Info);
            log.set_severity_text("INFO");
            log.set_timestamp(UNIX_EPOCH + Duration::from_millis(record.timestamp_unix_ms));
            log.set_observed_timestamp(SystemTime::now());
            log.set_body(AnyValue::from(json));
            log.add_attribute("g2.api_id", record.api_id.clone());
            log.add_attribute("g2.org_id", record.org_id.clone());
            log.add_attribute("http.response.status_code", i64::from(record.status));
            self.logger.emit(log);
        }
        Ok(()) // the batch processor buffers; export failures surface there
    }

    fn shutdown(&self) {
        if let Err(err) = self.provider.shutdown() {
            tracing::warn!(error = %err, "OTLP log exporter shutdown failed");
        }
    }
}

/// Hands `buf` to the sink and clears it; a failed delivery drops the
/// batch (logged) — analytics never backpressures the proxy.
async fn flush(sink: &dyn AnalyticsSink, buf: &mut Vec<AnalyticsRecord>) {
    if buf.is_empty() {
        return;
    }
    if let Err(err) = sink.emit(buf).await {
        tracing::warn!(
            sink = sink.name(),
            records = buf.len(),
            error = %err,
            "analytics batch dropped"
        );
    }
    buf.clear();
}

/// The process-wide analytics worker: drains `rx` into `sink` in batches
/// (currently up to 512 records), flushing at least once per second.
///
/// Runs until `stop` fires (or its sender is dropped, or every producer
/// handle is gone), then drains what is already queued, flushes it, and
/// shuts the sink down. The gateway binary spawns this once and signals
/// `stop` after the listeners have drained, so records from in-flight
/// requests still make it out.
pub async fn run(
    mut rx: mpsc::Receiver<AnalyticsRecord>,
    mut stop: watch::Receiver<()>,
    sink: Arc<dyn AnalyticsSink>,
) {
    let mut buf: Vec<AnalyticsRecord> = Vec::with_capacity(BATCH_SIZE);
    let mut tick = tokio::time::interval(FLUSH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.reset(); // the first interval tick fires immediately; skip it

    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Some(record) => {
                    buf.push(record);
                    if buf.len() >= BATCH_SIZE {
                        flush(sink.as_ref(), &mut buf).await;
                    }
                }
                None => break, // every producer handle dropped
            },
            _ = tick.tick() => flush(sink.as_ref(), &mut buf).await,
            _ = stop.changed() => break,
        }
    }

    // Shutdown: take everything already queued, then flush once.
    while let Ok(record) = rx.try_recv() {
        buf.push(record);
        if buf.len() >= BATCH_SIZE {
            flush(sink.as_ref(), &mut buf).await;
        }
    }
    flush(sink.as_ref(), &mut buf).await;
    sink.shutdown();
    tracing::debug!(sink = sink.name(), "analytics worker stopped");
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use g2_storage::{MemoryStorage, Storage as _};

    use super::*;

    fn record(org_id: &str, api_id: &str) -> AnalyticsRecord {
        AnalyticsRecord {
            timestamp_unix_ms: 1_756_600_000_000,
            api_id: api_id.into(),
            org_id: org_id.into(),
            method: "GET".into(),
            path: "/x".into(),
            status: 200,
            latency_ms: 5,
            upstream_latency_ms: None,
            key_hash: None,
            key_alias: None,
            client_ip: None,
            user_agent: None,
            request_content_length: None,
            response_content_length: None,
        }
    }

    /// Collects emitted batches; optionally fails every emit.
    #[derive(Debug, Default)]
    struct CollectingSink {
        batches: Mutex<Vec<Vec<AnalyticsRecord>>>,
        fail: bool,
        shutdowns: std::sync::atomic::AtomicU32,
    }

    #[async_trait::async_trait]
    impl AnalyticsSink for CollectingSink {
        fn name(&self) -> &'static str {
            "collect"
        }

        async fn emit(&self, records: &[AnalyticsRecord]) -> Result<(), AnalyticsSinkError> {
            if self.fail {
                return Err(AnalyticsSinkError("boom".into()));
            }
            self.batches
                .lock()
                .expect("batches lock")
                .push(records.to_vec());
            Ok(())
        }

        fn shutdown(&self) {
            self.shutdowns
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn worker_flushes_on_stop_and_shuts_the_sink_down() {
        let sink = Arc::new(CollectingSink::default());
        let (tx, rx) = mpsc::channel(16);
        let (stop_tx, stop_rx) = watch::channel(());

        let worker = tokio::spawn(run(
            rx,
            stop_rx,
            Arc::clone(&sink) as Arc<dyn AnalyticsSink>,
        ));
        tx.send(record("o", "a")).await.expect("send");
        tx.send(record("o", "b")).await.expect("send");
        stop_tx.send(()).expect("stop");
        worker.await.expect("worker task");

        let batches = sink.batches.lock().expect("batches lock");
        let total: usize = batches.iter().map(Vec::len).sum();
        assert_eq!(total, 2, "both records flushed at shutdown: {batches:?}");
        assert_eq!(
            sink.shutdowns.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "sink shut down exactly once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn worker_flushes_on_the_interval_without_a_stop() {
        let sink = Arc::new(CollectingSink::default());
        let (tx, rx) = mpsc::channel(16);
        let (_stop_tx, stop_rx) = watch::channel(());

        let _worker = tokio::spawn(run(
            rx,
            stop_rx,
            Arc::clone(&sink) as Arc<dyn AnalyticsSink>,
        ));
        tx.send(record("o", "a")).await.expect("send");
        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_millis(100)).await;

        let batches = sink.batches.lock().expect("batches lock");
        assert_eq!(batches.len(), 1, "one interval flush: {batches:?}");
        assert_eq!(batches[0].len(), 1);
    }

    #[tokio::test]
    async fn worker_survives_a_failing_sink() {
        let sink = Arc::new(CollectingSink {
            fail: true,
            ..CollectingSink::default()
        });
        let (tx, rx) = mpsc::channel(16);
        let (stop_tx, stop_rx) = watch::channel(());

        let worker = tokio::spawn(run(
            rx,
            stop_rx,
            Arc::clone(&sink) as Arc<dyn AnalyticsSink>,
        ));
        tx.send(record("o", "a")).await.expect("send");
        stop_tx.send(()).expect("stop");
        worker.await.expect("worker survives emit errors");
    }

    #[tokio::test]
    async fn redis_list_sink_groups_records_per_org_and_caps() {
        let storage = MemoryStorage::new();
        let shared: SharedStorage = Arc::new(storage.clone());
        let sink = RedisListSink::new(shared).with_max_records(2);

        sink.emit(&[
            record("acme", "a1"),
            record("beta", "b1"),
            record("acme", "a2"),
        ])
        .await
        .expect("emit");
        sink.emit(&[record("acme", "a3")]).await.expect("emit more");

        // Cap of 2 kept only the newest two acme records.
        let acme = storage
            .list_drain(&analytics_records_key("acme"), 10)
            .await
            .expect("drain");
        let api_ids: Vec<String> = acme
            .iter()
            .map(|json| {
                serde_json::from_str::<AnalyticsRecord>(json)
                    .expect("stored records are valid JSON")
                    .api_id
            })
            .collect();
        assert_eq!(api_ids, ["a2", "a3"]);

        let beta = storage
            .list_drain(&analytics_records_key("beta"), 10)
            .await
            .expect("drain");
        assert_eq!(beta.len(), 1, "beta records landed on beta's list");
    }

    #[test]
    fn logs_endpoint_appends_signal_path_idempotently() {
        assert_eq!(
            logs_endpoint("http://collector:4318"),
            "http://collector:4318/v1/logs"
        );
        assert_eq!(
            logs_endpoint("http://collector:4318/v1/logs/"),
            "http://collector:4318/v1/logs"
        );
    }

    #[test]
    fn otlp_logs_sink_exports_records_to_the_collector() {
        let (endpoint, rx) = crate::otlp::tests::fake_collector();
        let sink = OtlpLogsSink::new(&OtlpConfig { endpoint }).expect("sink");

        // emit() is async only for the trait's sake; drive it trivially.
        futures_executor_block_on(sink.emit(&[record("acme", "users-api")])).expect("emit");
        sink.shutdown(); // flushes the batch processor

        let head = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("collector saw a request");
        assert!(head.starts_with("POST /v1/logs"), "request head:\n{head}");
    }

    /// Minimal block_on: the OTLP sink's `emit` never awaits anything.
    fn futures_executor_block_on<F: std::future::Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(out) => out,
            std::task::Poll::Pending => unreachable!("OtlpLogsSink::emit never yields"),
        }
    }
}
