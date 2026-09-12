//! The gateway's accept loop and graceful shutdown handling.

use std::convert::Infallible;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use g2_proxy::Gateway;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;

/// Serves `gateway` on `listener` until `shutdown` resolves, then drains.
///
/// Each accepted connection is served on its own task (HTTP/1.1 and HTTP/2
/// are auto-detected). When `shutdown` resolves the accept loop stops and
/// in-flight requests get up to `grace` to finish — the k8s-friendly
/// SIGTERM drain behavior.
///
/// # Errors
///
/// Returns an error only if accepting on `listener` fails fatally.
pub async fn serve(
    listener: TcpListener,
    gateway: Arc<Gateway>,
    shutdown: impl std::future::Future<Output = ()> + Send,
    grace: Duration,
) -> std::io::Result<()> {
    let graceful = GracefulShutdown::new();
    let mut shutdown = pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, remote_addr) = accepted?;
                let io = TokioIo::new(stream);
                let gateway = Arc::clone(&gateway);
                let service = service_fn(move |req| {
                    let gateway = Arc::clone(&gateway);
                    async move { Ok::<_, Infallible>(gateway.handle(req, remote_addr).await) }
                });
                let builder = auto::Builder::new(TokioExecutor::new());
                let conn = builder.serve_connection(io, service);
                let conn = graceful.watch(conn.into_owned());
                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        // Client disconnects and protocol errors are normal
                        // churn, not gateway failures.
                        tracing::debug!(%remote_addr, error = %err, "connection ended with error");
                    }
                });
            }
            () = &mut shutdown => {
                tracing::info!("shutdown signal received; draining connections");
                break;
            }
        }
    }

    tokio::select! {
        () = graceful.shutdown() => {
            tracing::info!("all connections drained");
        }
        () = tokio::time::sleep(grace) => {
            tracing::warn!(grace_secs = grace.as_secs(), "grace period expired; closing remaining connections");
        }
    }
    Ok(())
}

/// Resolves when the process receives `SIGTERM` (k8s pod stop) or `SIGINT`
/// (Ctrl-C during local development).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        _ = terminate => {}
    }
}
