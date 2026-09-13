//! The g2way gateway binary.
//!
//! Parses CLI flags / environment variables, loads the gateway config and
//! API definitions, and runs the server (see [`g2way::server`]).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use g2_core::config::AnalyticsSinkKind;
use g2_core::GatewayConfig;
use g2_proxy::{Forwarder, Gateway};
use g2_storage::{MemoryStorage, RedisStorage, SharedStorage};
use g2_telemetry::LogFormat;
use g2way::{reload, server};

/// g2way — an API gateway written in Rust.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Path to a gateway config file (YAML or JSON).
    #[arg(long, env = "G2_CONFIG")]
    config: Option<PathBuf>,

    /// Proxy listen address, e.g. 0.0.0.0:8080 (overrides the config file).
    #[arg(long, env = "G2_LISTEN")]
    listen: Option<SocketAddr>,

    /// Directory containing API definition files (overrides the config file).
    #[arg(long, env = "G2_APPS_DIR")]
    apps_dir: Option<PathBuf>,

    /// Redis URL for shared key/counter storage (overrides the config file).
    /// Without one, storage is in-memory: per-pod and lost on restart.
    #[arg(long, env = "G2_REDIS_URL")]
    redis_url: Option<String>,

    /// Admin API listen address, e.g. 127.0.0.1:9696 (overrides the config
    /// file). The admin API is disabled unless an address is configured, and
    /// requires an admin secret.
    #[arg(long, env = "G2_ADMIN_LISTEN")]
    admin_listen: Option<SocketAddr>,

    /// Secret admin requests must present in `X-G2-Authorization`
    /// (overrides the config file).
    #[arg(long, env = "G2_ADMIN_SECRET", hide_env_values = true)]
    admin_secret: Option<String>,

    /// Base endpoint of an OTLP/HTTP collector for trace export, e.g.
    /// http://otel-collector:4318 (overrides the config file). Without one,
    /// spans are not exported.
    #[arg(long, env = "G2_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,

    /// Analytics sink for per-request records: `stdout`, `redis`, or
    /// `otlp_logs` (overrides the config file). Without one, no analytics
    /// records are produced.
    #[arg(long, env = "G2_ANALYTICS_SINK")]
    analytics_sink: Option<AnalyticsSinkKind>,

    /// Log output format: `json` (default) or `pretty`.
    #[arg(long, env = "G2_LOG_FORMAT", default_value = "json")]
    log_format: LogFormat,
}

/// Records buffered between the proxy path and the analytics worker. At
/// ~500 bytes a record this bounds the buffer around 4 MB; when the worker
/// falls further behind, records are dropped (counted), never blocking a
/// request.
const ANALYTICS_CHANNEL_CAPACITY: usize = 8192;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // stderr, not tracing: failures this early can predate the
            // subscriber (config errors), and it must never be silent.
            eprintln!("g2way: failed to start: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Loads configuration and runs the gateway to completion.
fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = match &cli.config {
        Some(path) => GatewayConfig::from_file(path)?,
        None => GatewayConfig::default(),
    };
    if let Some(listen) = cli.listen {
        config.listen_addr = listen;
    }
    if let Some(apps_dir) = cli.apps_dir {
        config.apps_dir = apps_dir;
    }
    if let Some(redis_url) = cli.redis_url {
        config.redis_url = Some(redis_url);
    }
    if let Some(admin_listen) = cli.admin_listen {
        config.admin_listen_addr = Some(admin_listen);
    }
    if let Some(admin_secret) = cli.admin_secret {
        config.admin_secret = Some(admin_secret);
    }
    if let Some(otlp_endpoint) = cli.otlp_endpoint {
        config.otlp_endpoint = Some(otlp_endpoint);
    }
    if let Some(analytics_sink) = cli.analytics_sink {
        config.analytics_sink = Some(analytics_sink);
    }
    config.validate()?;

    // The OTLP exporters batch on their own threads (no tokio dependency),
    // so telemetry is deliberately initialized before the runtime exists and
    // flushed after it is gone. The Prometheus pull side is enabled exactly
    // when the admin listener is: that is the port serving `GET /metrics`.
    let otlp = config
        .otlp_endpoint
        .clone()
        .map(|endpoint| g2_telemetry::OtlpConfig { endpoint });
    let prometheus_enabled = config.admin_listen_addr.is_some();
    let telemetry =
        g2_telemetry::init_telemetry(cli.log_format, otlp.as_ref(), prometheus_enabled)?;
    if let Some(cfg) = &otlp {
        tracing::info!(endpoint = %cfg.endpoint, "OTLP trace and metric export enabled");
    }
    // Request instruments bind to the global meter provider installed just
    // above; without any metrics side enabled they would no-op, so skip them.
    let metrics =
        (otlp.is_some() || prometheus_enabled).then(|| Arc::new(g2_middleware::HttpMetrics::new()));
    let prometheus = telemetry.prometheus();

    let grace = Duration::from_secs(config.shutdown_grace_period_secs);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let storage: SharedStorage = match &config.redis_url {
            Some(url) => {
                let storage = RedisStorage::connect(url).await?;
                tracing::info!("connected to Redis storage");
                Arc::new(storage)
            }
            None => {
                tracing::warn!(
                    "no redis_url configured: using in-memory storage \
                     (API keys are per-process and lost on restart)"
                );
                Arc::new(MemoryStorage::new())
            }
        };
        let spike_guard = config.spike_guard.as_ref().map(|cfg| {
            tracing::info!(
                capacity = cfg.capacity,
                refill_per_sec = cfg.refill_per_sec,
                "spike guard enabled"
            );
            Arc::new(g2_middleware::SpikeGuard::new(cfg))
        });
        // Analytics: one process-wide worker drains a bounded channel into
        // the configured sink; every route's analytics layer feeds the
        // channel through a cheap-clone handle.
        let sink: Option<Arc<dyn g2_telemetry::AnalyticsSink>> = match config.analytics_sink {
            None => None,
            Some(AnalyticsSinkKind::Stdout) => Some(Arc::new(g2_telemetry::StdoutJsonSink::new())),
            Some(AnalyticsSinkKind::Redis) => Some(Arc::new(g2_telemetry::RedisListSink::new(
                Arc::clone(&storage),
            ))),
            Some(AnalyticsSinkKind::OtlpLogs) => {
                let cfg = otlp
                    .as_ref()
                    .expect("validate() guarantees otlp_endpoint for the otlp_logs sink");
                Some(Arc::new(g2_telemetry::OtlpLogsSink::new(cfg)?))
            }
        };
        let mut analytics = None;
        let mut analytics_worker = None;
        if let Some(sink) = sink {
            tracing::info!(sink = sink.name(), "analytics records enabled");
            let (handle, rx) = g2_middleware::AnalyticsHandle::channel(ANALYTICS_CHANNEL_CAPACITY);
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
            let worker = tokio::spawn(g2_telemetry::analytics::run(rx, stop_rx, sink));
            analytics = Some(handle);
            analytics_worker = Some((stop_tx, worker));
        }

        let stats = Arc::new(g2_middleware::StatsRegistry::new());
        // Both definition sources (files + storage, ADR-0002) are loaded
        // through the reload context, at startup and on every reload nudge.
        let reload_ctx = reload::ReloadContext {
            apps_dir: config.apps_dir.clone(),
            org_id: g2_core::DEFAULT_ORG_ID.to_owned(),
            storage: Arc::clone(&storage),
            forwarder: Forwarder::new(),
            spike_guard,
            stats: Some(Arc::clone(&stats)),
            metrics,
            analytics,
        };
        let gateway = Arc::new(Gateway::new(reload_ctx.build_table().await?));
        tracing::info!(apps_dir = %config.apps_dir.display(), "API definitions loaded");

        // Hot reload: `POST /g2/reload` on any pod's admin API broadcasts
        // a nudge; this task rebuilds and swaps the route table on each.
        {
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move {
                if let Err(e) = reload::listen(reload_ctx, gateway).await {
                    tracing::error!(error = %e, "reload subscription failed; hot reload disabled");
                }
            });
        }

        let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
        tracing::info!(
            listen_addr = %config.listen_addr,
            routes = gateway.route_count(),
            version = env!("CARGO_PKG_VERSION"),
            "g2way listening"
        );

        // One OS signal fans out to every listener's graceful shutdown.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
        tokio::spawn(async move {
            server::shutdown_signal().await;
            let _ = shutdown_tx.send(());
        });
        let wait_for_shutdown = |mut rx: tokio::sync::watch::Receiver<()>| async move {
            // Resolves on the signal, or if the sender task ever vanished.
            let _ = rx.changed().await;
        };

        let proxy = server::serve(
            listener,
            Arc::clone(&gateway),
            wait_for_shutdown(shutdown_rx.clone()),
            grace,
        );
        match &config.admin_listen_addr {
            Some(admin_addr) => {
                let secret = config
                    .admin_secret
                    .as_deref()
                    .expect("validate() guarantees a secret when the admin listener is set");
                let dashboard = g2_admin::Dashboard::new(Arc::clone(&gateway), Arc::clone(&stats));
                let admin_router = g2_admin::router(
                    secret,
                    Arc::clone(&storage),
                    Some(dashboard),
                    prometheus.clone(),
                )?;
                let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
                tracing::info!(admin_listen_addr = %admin_addr, "admin API listening");
                let admin = g2_admin::serve(
                    admin_listener,
                    admin_router,
                    wait_for_shutdown(shutdown_rx.clone()),
                );
                tokio::try_join!(proxy, admin)?;
            }
            None => proxy.await?,
        }
        // The listeners have drained: stop the analytics worker, which
        // flushes queued records and shuts its sink down before we return.
        if let Some((stop_tx, worker)) = analytics_worker {
            let _ = stop_tx.send(());
            let _ = worker.await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    tracing::info!("g2way stopped");
    telemetry.shutdown();
    Ok(())
}
