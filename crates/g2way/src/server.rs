//! The gateway's accept loop and graceful shutdown handling.

use std::convert::Infallible;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use g2_middleware::ConnectionInfo;
use g2_proxy::Gateway;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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
    serve_inner(listener, gateway, None, shutdown, grace).await
}

/// [`serve`] with TLS termination: every accepted connection must complete
/// a TLS handshake through `acceptor` before it is served.
///
/// The handshake runs on the connection's own task (a slow or stuck
/// handshake never blocks the accept loop) under
/// [`crate::tls::HANDSHAKE_TIMEOUT`]. When the handshake verified a client
/// certificate, its SHA-256 fingerprint is stamped onto every request of
/// the connection via [`ConnectionInfo`] for the `mtls` auth mode.
///
/// Graceful-shutdown nuance: connections still mid-handshake when
/// `shutdown` resolves are not part of the drain — they either finish
/// handshaking and get served (their drain watcher was taken at accept
/// time) or die with the process when `grace` expires. A client dribbling
/// its handshake can therefore never stall shutdown.
///
/// # Errors
///
/// Returns an error only if accepting on `listener` fails fatally
/// (individual handshake failures are logged and dropped).
pub async fn serve_tls(
    listener: TcpListener,
    gateway: Arc<Gateway>,
    acceptor: TlsAcceptor,
    shutdown: impl std::future::Future<Output = ()> + Send,
    grace: Duration,
) -> std::io::Result<()> {
    serve_inner(listener, gateway, Some(acceptor), shutdown, grace).await
}

async fn serve_inner(
    listener: TcpListener,
    gateway: Arc<Gateway>,
    tls: Option<TlsAcceptor>,
    shutdown: impl std::future::Future<Output = ()> + Send,
    grace: Duration,
) -> std::io::Result<()> {
    let graceful = GracefulShutdown::new();
    let mut shutdown = pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, remote_addr) = accepted?;
                let gateway = Arc::clone(&gateway);
                let tls = tls.clone();
                // The watcher is cloned per connection and moved into its
                // task; `graceful.shutdown()` resolves once every clone is
                // dropped (i.e. every watched connection has drained).
                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    let (conn_info, result) = match tls {
                        None => {
                            let io = TokioIo::new(stream);
                            let conn_info = ConnectionInfo::default();
                            let result = serve_connection(io, gateway, remote_addr, conn_info.clone(), watcher).await;
                            (conn_info, result)
                        }
                        Some(acceptor) => {
                            let handshake = tokio::time::timeout(
                                crate::tls::HANDSHAKE_TIMEOUT,
                                acceptor.accept(stream),
                            );
                            let tls_stream = match handshake.await {
                                Ok(Ok(tls_stream)) => tls_stream,
                                Ok(Err(err)) => {
                                    // Failed handshakes (bad cert, protocol
                                    // mismatch, port scans) are client churn,
                                    // not gateway failures.
                                    tracing::debug!(%remote_addr, error = %err, "TLS handshake failed");
                                    return;
                                }
                                Err(_elapsed) => {
                                    tracing::debug!(%remote_addr, "TLS handshake timed out");
                                    return;
                                }
                            };
                            let conn_info = ConnectionInfo {
                                tls: true,
                                client_cert_fingerprint: tls_stream
                                    .get_ref()
                                    .1
                                    .peer_certificates()
                                    .and_then(|certs| certs.first())
                                    .map(|cert| {
                                        g2_core::session::cert_fingerprint_hex(cert.as_ref()).into()
                                    }),
                            };
                            let io = TokioIo::new(tls_stream);
                            let result = serve_connection(io, gateway, remote_addr, conn_info.clone(), watcher).await;
                            (conn_info, result)
                        }
                    };
                    if let Err(err) = result {
                        // Client disconnects and protocol errors are normal
                        // churn, not gateway failures.
                        tracing::debug!(
                            %remote_addr,
                            tls = conn_info.tls,
                            error = %err,
                            "connection ended with error"
                        );
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

/// Serves one (possibly TLS-wrapped) connection to completion, stamping
/// `conn_info` onto every request it carries.
async fn serve_connection<I>(
    io: I,
    gateway: Arc<Gateway>,
    remote_addr: std::net::SocketAddr,
    conn_info: ConnectionInfo,
    watcher: hyper_util::server::graceful::Watcher,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let gateway = Arc::clone(&gateway);
        let conn_info = conn_info.clone();
        async move { Ok::<_, Infallible>(gateway.handle(req, remote_addr, conn_info).await) }
    });
    let builder = auto::Builder::new(TokioExecutor::new());
    let conn = builder.serve_connection(io, service);
    watcher.watch(conn.into_owned()).await
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
