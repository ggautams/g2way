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
use g2_core::GatewayConfig;
use g2_proxy::{Gateway, RouteTable};
use g2_telemetry::LogFormat;
use g2way::server;

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

    /// Log output format: `json` (default) or `pretty`.
    #[arg(long, env = "G2_LOG_FORMAT", default_value = "json")]
    log_format: LogFormat,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    g2_telemetry::init_tracing(cli.log_format);

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "gateway failed to start");
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

    let defs = g2_core::loader::load_dir(&config.apps_dir)?;
    tracing::info!(
        count = defs.len(),
        apps_dir = %config.apps_dir.display(),
        "loaded API definitions"
    );
    let table = RouteTable::build(defs)?;
    let gateway = Arc::new(Gateway::new(table));
    let grace = Duration::from_secs(config.shutdown_grace_period_secs);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
        tracing::info!(
            listen_addr = %config.listen_addr,
            routes = gateway.route_count(),
            version = env!("CARGO_PKG_VERSION"),
            "g2way listening"
        );
        server::serve(listener, gateway, server::shutdown_signal(), grace).await
    })?;
    tracing::info!("g2way stopped");
    Ok(())
}
