//! Active upstream health checking: per-address probing and eviction.
//!
//! An API with a [`HealthCheckConfig`] gets one checker task per forwarding
//! [`UpstreamTarget`] (spawned at route-build time). Every interval the task
//! probes each upstream address with `GET {base_path}{path}` through the
//! shared [`Forwarder`] client; addresses failing enough consecutive probes
//! are marked unhealthy in the target's [`HealthState`], which
//! [`UpstreamTarget::next_addr`](crate::UpstreamTarget::next_addr) skips
//! until the checker reinstates them.
//!
//! Lifecycle: the task holds only a [`Weak`] reference to its target, so a
//! config reload that drops the old route table lets the old checker exit on
//! its next tick — no explicit abort plumbing. Eviction is pod-local, like
//! the round-robin rotation itself.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use g2_core::HealthCheckConfig;
use g2_middleware::ProxyBody;
use http::{Method, Request, Uri};

use crate::forward::{Forwarder, UpstreamAddr, UpstreamClient, UpstreamTarget};

/// Live health flags for one target's upstream addresses, indexed like
/// [`UpstreamTarget::targets`](crate::UpstreamTarget::targets).
///
/// Written by the checker task, read lock-free by `next_addr()` on the hot
/// path. Every address starts healthy: a freshly loaded config must not
/// refuse traffic before the first probe round has run.
#[derive(Debug)]
pub(crate) struct HealthState {
    flags: Vec<AtomicBool>,
}

impl HealthState {
    /// A state for `count` addresses, all initially healthy.
    pub(crate) fn new(count: usize) -> Self {
        Self {
            flags: (0..count).map(|_| AtomicBool::new(true)).collect(),
        }
    }

    /// Whether the address at `index` is currently in the rotation.
    pub(crate) fn is_healthy(&self, index: usize) -> bool {
        self.flags[index].load(Ordering::Relaxed)
    }

    /// Marks the address at `index` healthy or evicted.
    pub(crate) fn set_healthy(&self, index: usize, healthy: bool) {
        self.flags[index].store(healthy, Ordering::Relaxed);
    }

    /// The current flags, in address order.
    pub(crate) fn snapshot(&self) -> Vec<bool> {
        self.flags
            .iter()
            .map(|f| f.load(Ordering::Relaxed))
            .collect()
    }
}

/// Consecutive probe outcomes for one address (checker-task-local; only the
/// resulting healthy flag is shared).
#[derive(Default)]
struct Streak {
    failures: u32,
    successes: u32,
}

/// Spawns the probe loop for `target`, if it carries health state.
///
/// Returns the task handle, or `None` when the target has no health state or
/// no tokio runtime is running (synchronous route builds in tests — the
/// binary always builds tables inside the runtime).
pub(crate) fn spawn_checker(
    forwarder: &Forwarder,
    target: &Arc<UpstreamTarget>,
    cfg: &HealthCheckConfig,
) -> Option<tokio::task::JoinHandle<()>> {
    let state = Arc::clone(target.health.as_ref()?);
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            api_id = %target.api_id,
            "no tokio runtime available; upstream health checks stay disabled"
        );
        return None;
    };
    let uris: Vec<Uri> = target
        .targets
        .iter()
        .map(|addr| probe_uri(addr, &cfg.path))
        .collect();
    Some(handle.spawn(run_checker(
        // Probes must speak the target's protocol: a pure-HTTP/2 upstream
        // rejects HTTP/1.1 probes, which would evict every address.
        forwarder.client_for(target).clone(),
        Arc::downgrade(target),
        state,
        uris,
        target.api_id.clone(),
        cfg.clone(),
    )))
}

/// The probe URL for one address: its base path joined with the configured
/// health path (both validated URI components).
fn probe_uri(addr: &UpstreamAddr, path: &str) -> Uri {
    Uri::builder()
        .scheme(addr.scheme.clone())
        .authority(addr.authority.clone())
        .path_and_query(format!("{}{path}", addr.base_path))
        .build()
        .expect("validated target parts and health path form a URI")
}

/// The checker task: probes every address each interval and applies the
/// threshold transitions, until `target` is dropped (route table swap).
async fn run_checker(
    client: UpstreamClient,
    target: Weak<UpstreamTarget>,
    state: Arc<HealthState>,
    uris: Vec<Uri>,
    api_id: String,
    cfg: HealthCheckConfig,
) {
    let interval = Duration::from_millis(cfg.interval_ms);
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let mut streaks: Vec<Streak> = uris.iter().map(|_| Streak::default()).collect();
    loop {
        tokio::time::sleep(interval).await;
        if target.strong_count() == 0 {
            tracing::debug!(%api_id, "target dropped; stopping upstream health checks");
            return;
        }
        let results =
            futures_util::future::join_all(uris.iter().map(|uri| probe(&client, uri, timeout)))
                .await;
        for (index, healthy) in results.into_iter().enumerate() {
            let streak = &mut streaks[index];
            if healthy {
                streak.failures = 0;
                streak.successes = streak.successes.saturating_add(1);
                if !state.is_healthy(index) && streak.successes >= cfg.healthy_threshold {
                    state.set_healthy(index, true);
                    tracing::info!(%api_id, target = %uris[index], "upstream address reinstated");
                }
            } else {
                streak.successes = 0;
                streak.failures = streak.failures.saturating_add(1);
                if state.is_healthy(index) && streak.failures >= cfg.unhealthy_threshold {
                    state.set_healthy(index, false);
                    tracing::warn!(
                        %api_id,
                        target = %uris[index],
                        failures = streak.failures,
                        "upstream address evicted after consecutive probe failures"
                    );
                }
            }
        }
    }
}

/// One probe: `GET uri` within `timeout`; only a `2xx` answer is healthy.
async fn probe(client: &UpstreamClient, uri: &Uri, timeout: Duration) -> bool {
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(ProxyBody::empty())
        .expect("a GET request from a valid URI is well-formed");
    matches!(
        tokio::time::timeout(timeout, client.request(req)).await,
        Ok(Ok(resp)) if resp.status().is_success()
    )
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::{Ipv4Addr, SocketAddr};

    use g2_core::ApiDefinition;
    use http::{Response, StatusCode};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use super::*;

    /// Serves `200` while the returned flag is `true`, else `500`.
    async fn spawn_toggle_upstream() -> (SocketAddr, Arc<AtomicBool>) {
        let flag = Arc::new(AtomicBool::new(true));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let served = Arc::clone(&flag);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let served = Arc::clone(&served);
                tokio::spawn(async move {
                    let service = service_fn(move |_req| {
                        let up = served.load(Ordering::Relaxed);
                        async move {
                            let status = if up {
                                StatusCode::OK
                            } else {
                                StatusCode::INTERNAL_SERVER_ERROR
                            };
                            let mut resp =
                                Response::new(http_body_util::Empty::<bytes::Bytes>::new());
                            *resp.status_mut() = status;
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (addr, flag)
    }

    fn checked_target(
        targets: &[SocketAddr],
        cfg_json: &str,
    ) -> (Arc<UpstreamTarget>, HealthCheckConfig) {
        let list: Vec<String> = targets.iter().map(|a| format!("http://{a}")).collect();
        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"hc","name":"hc","listen_path":"/hc/",
                "target_url":"http://unused.internal",
                "target_list":{},
                "health_check":{cfg_json}}}"#,
            serde_json::to_string(&list).expect("json"),
        ))
        .expect("def");
        let cfg = def.health_check.clone().expect("set");
        (Arc::new(UpstreamTarget::build(&def).expect("target")), cfg)
    }

    /// Polls until the target's health snapshot equals `want` (or panics).
    async fn wait_for_health(target: &UpstreamTarget, want: &[bool]) {
        for _ in 0..400 {
            if target.target_health().as_deref() == Some(want) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "health never reached {want:?}, still {:?}",
            target.target_health()
        );
    }

    #[tokio::test]
    async fn checker_evicts_and_reinstates_on_thresholds() {
        let (toggle, flag) = spawn_toggle_upstream().await;
        let (steady, _steady_flag) = spawn_toggle_upstream().await;
        let (target, cfg) = checked_target(
            &[toggle, steady],
            r#"{"interval_ms": 20, "timeout_ms": 250, "unhealthy_threshold": 2, "healthy_threshold": 2}"#,
        );
        flag.store(false, Ordering::Relaxed);
        let handle = spawn_checker(&Forwarder::new(), &target, &cfg).expect("spawned");

        // Two failed rounds evict the toggling address; the steady one stays.
        wait_for_health(&target, &[false, true]).await;

        // Two healthy rounds reinstate it.
        flag.store(true, Ordering::Relaxed);
        wait_for_health(&target, &[true, true]).await;

        // Dropping the last target handle stops the checker on its next tick.
        drop(target);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("checker must exit once its target is dropped")
            .expect("checker task must not panic");
    }

    #[tokio::test]
    async fn unreachable_address_counts_as_probe_failure() {
        // Bind-then-drop a listener to obtain a port with nothing behind it.
        let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let dead_addr = dead.local_addr().expect("addr");
        drop(dead);
        let (live, _flag) = spawn_toggle_upstream().await;

        let (target, cfg) = checked_target(
            &[dead_addr, live],
            r#"{"interval_ms": 20, "timeout_ms": 250, "unhealthy_threshold": 1, "healthy_threshold": 1}"#,
        );
        spawn_checker(&Forwarder::new(), &target, &cfg).expect("spawned");
        wait_for_health(&target, &[false, true]).await;
    }

    #[test]
    fn probe_uri_joins_base_path_and_health_path() {
        let addr = UpstreamAddr {
            scheme: http::uri::Scheme::HTTP,
            authority: "up.internal:8080".parse().expect("authority"),
            base_path: "/base".into(),
        };
        assert_eq!(
            probe_uri(&addr, "/health?deep=1").to_string(),
            "http://up.internal:8080/base/health?deep=1"
        );
        let bare = UpstreamAddr {
            base_path: String::new(),
            ..addr
        };
        assert_eq!(
            probe_uri(&bare, "/").to_string(),
            "http://up.internal:8080/"
        );
    }
}
