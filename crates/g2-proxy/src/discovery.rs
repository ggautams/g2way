//! Upstream service discovery: HTTP+JSON polling with live target swaps.
//!
//! An API with a [`ServiceDiscoveryConfig`] gets one refresher task per
//! forwarding [`UpstreamTarget`] (spawned at route-build time). The task
//! polls the configured endpoint — immediately once, then every interval —
//! extracts the current upstream addresses from the JSON response
//! ([`ServiceDiscoveryConfig::extract_entries`]), and, when they differ from
//! the mounted [`TargetSet`], swaps in a fresh set wholesale (ADR-0006's
//! one designated swappable leaf; the route table itself is untouched).
//!
//! Failure policy is stale-on-error, mirroring the JWKS refresher: a fetch
//! error, non-2xx answer, oversized/unparseable body, extraction error,
//! invalid entry, or an *empty* result keeps the previous set and logs a
//! warning — stale targets beat empty targets, so discovery can never leave
//! a target with nothing to forward to. Until the first successful poll the
//! target serves its static seeds (`target_list`/`target_url`).
//!
//! Lifecycle: the task holds only a [`Weak`] reference to its target, so a
//! config reload that drops the old route table lets the old refresher exit
//! on its next poll — the health-checker pattern. Polling is pod-local
//! (each pod polls the endpoint itself, like health probing), and the
//! endpoint is always fetched over the HTTP/1.1 pool regardless of the
//! API's `upstream_http2` setting.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use g2_core::{DiscoveredEntry, ServiceDiscoveryConfig};
use g2_middleware::ProxyBody;
use http::uri::{Authority, Scheme};
use http::{Method, Request, Uri};

use crate::forward::{Forwarder, TargetSet, UpstreamAddr, UpstreamClient, UpstreamTarget};

/// Largest discovery response body accepted (catalogs are small; a huge
/// answer is a misconfigured endpoint, not a bigger cluster).
const MAX_DISCOVERY_BYTES: usize = 1024 * 1024;

/// Live status of one target's discovery refresher, written by the task and
/// read by dashboard snapshots.
#[derive(Debug, Default)]
pub(crate) struct DiscoveryStatus {
    /// Unix seconds of the last successful poll; `0` = none yet.
    last_success_secs: AtomicU64,
    /// The most recent poll failure; cleared by the next success.
    last_error: ArcSwapOption<String>,
}

impl DiscoveryStatus {
    fn record_success(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.last_success_secs.store(now, Ordering::Relaxed);
        self.last_error.store(None);
    }

    fn record_error(&self, error: String) {
        self.last_error.store(Some(Arc::new(error)));
    }

    /// The current status, for dashboards.
    pub(crate) fn snapshot(&self) -> DiscoverySnapshot {
        let secs = self.last_success_secs.load(Ordering::Relaxed);
        DiscoverySnapshot {
            last_success_unix_secs: (secs != 0).then_some(secs),
            last_error: self
                .last_error
                .load_full()
                .map(|error| error.as_ref().clone()),
        }
    }
}

/// A point-in-time view of one target's service-discovery status (see
/// [`UpstreamTarget::discovery_status`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverySnapshot {
    /// Unix seconds of the last successful poll; `None` while the target is
    /// still serving its static seed addresses.
    pub last_success_unix_secs: Option<u64>,
    /// The most recent poll failure, if the latest poll failed.
    pub last_error: Option<String>,
}

/// Spawns the polling loop for `target`, if discovery is active for it.
///
/// Returns the task handle, or `None` when the target carries no discovery
/// status (the unused base target of a versioned API) or no tokio runtime
/// is running (synchronous route builds in tests — the binary always builds
/// tables inside the runtime).
pub(crate) fn spawn_refresher(
    forwarder: &Forwarder,
    target: &Arc<UpstreamTarget>,
    cfg: &ServiceDiscoveryConfig,
) -> Option<tokio::task::JoinHandle<()>> {
    target.discovery.as_ref()?;
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            api_id = %target.api_id,
            "no tokio runtime available; service discovery stays disabled"
        );
        return None;
    };
    Some(handle.spawn(run_refresher(
        // Discovery endpoints are ordinary JSON-over-HTTP services; they
        // ride the HTTP/1.1 pool like JWKS fetches, independent of the
        // API's upstream protocol.
        forwarder.client().clone(),
        Arc::downgrade(target),
        cfg.clone(),
    )))
}

/// The refresher task: polls immediately (traffic serves the static seeds
/// until the first success), then every interval, until `target` is dropped
/// (route table swap).
async fn run_refresher(
    client: UpstreamClient,
    target: Weak<UpstreamTarget>,
    cfg: ServiceDiscoveryConfig,
) {
    let interval = Duration::from_millis(cfg.interval_ms);
    loop {
        if !refresh_once(&client, &target, &cfg).await {
            return;
        }
        tokio::time::sleep(interval).await;
    }
}

/// One poll cycle: fetch, extract, and swap-on-change. Returns `false` once
/// the target is gone and the task should end.
async fn refresh_once(
    client: &UpstreamClient,
    target: &Weak<UpstreamTarget>,
    cfg: &ServiceDiscoveryConfig,
) -> bool {
    let Some(target) = target.upgrade() else {
        return false;
    };
    match poll_endpoint(client, cfg).await {
        Ok(addrs) => apply_addrs(&target, cfg, addrs),
        Err(error) => {
            tracing::warn!(
                api_id = %target.api_id,
                endpoint = %cfg.endpoint,
                %error,
                kept = target.target_set().addrs.len(),
                "service discovery poll failed; keeping previous targets"
            );
            if let Some(status) = &target.discovery {
                status.record_error(error);
            }
        }
    }
    true
}

/// Fetches and parses one discovery response into upstream addresses.
///
/// Any failure — transport, status, body size, JSON, extraction, entry
/// composition, or an empty result — fails the whole poll; the caller keeps
/// the previous addresses.
async fn poll_endpoint(
    client: &UpstreamClient,
    cfg: &ServiceDiscoveryConfig,
) -> Result<Vec<UpstreamAddr>, String> {
    let uri: Uri = cfg
        .endpoint
        .parse()
        .map_err(|e| format!("invalid discovery endpoint `{}`: {e}", cfg.endpoint))?;
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(ProxyBody::empty())
        .map_err(|e| format!("could not build discovery request: {e}"))?;
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let resp = tokio::time::timeout(timeout, client.request(req))
        .await
        .map_err(|_| format!("poll timed out after {timeout:?}"))?
        .map_err(|e| format!("poll failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("discovery endpoint answered {}", resp.status()));
    }
    let body = http_body_util::Limited::new(resp.into_body(), MAX_DISCOVERY_BYTES);
    let collected = http_body_util::BodyExt::collect(body)
        .await
        .map_err(|e| format!("reading discovery body failed: {e}"))?;
    let doc: serde_json::Value = serde_json::from_slice(&collected.to_bytes())
        .map_err(|e| format!("discovery response is not JSON: {e}"))?;
    let entries = cfg.extract_entries(&doc)?;
    if entries.is_empty() {
        return Err("discovery returned no addresses".into());
    }
    entries
        .iter()
        .map(|entry| entry_addr(entry, &cfg.scheme))
        .collect()
}

/// Composes one discovered entry into an upstream address.
///
/// A full `http(s)://` entry is used as-is (own scheme, port, and base
/// path; a resolved port is ignored for it); any other `://` scheme is
/// rejected. A bare `host`/`host:port` entry (IPv6 bracketed) gets the
/// configured scheme, the resolved port when the entry carries none, and an
/// empty base path.
fn entry_addr(entry: &DiscoveredEntry, scheme: &str) -> Result<UpstreamAddr, String> {
    let host = entry.host.trim();
    if host.contains("://") {
        return UpstreamAddr::try_from_url(host);
    }
    let authority: Authority = host
        .parse()
        .map_err(|e| format!("`{host}` is not a valid host: {e}"))?;
    let authority = match (entry.port, authority.port_u16()) {
        (Some(port), None) => format!("{host}:{port}")
            .parse()
            .map_err(|e| format!("`{host}:{port}` is not a valid authority: {e}"))?,
        _ => authority,
    };
    Ok(UpstreamAddr {
        scheme: if scheme == "https" {
            Scheme::HTTPS
        } else {
            Scheme::HTTP
        },
        authority,
        base_path: String::new(),
    })
}

/// Mounts `addrs` on the target unless they equal the current set (an
/// unchanged poll must not reset health flags or spam logs).
fn apply_addrs(target: &UpstreamTarget, cfg: &ServiceDiscoveryConfig, addrs: Vec<UpstreamAddr>) {
    let current = target.target_set_full();
    if current.addrs == addrs {
        tracing::debug!(
            api_id = %target.api_id,
            endpoint = %cfg.endpoint,
            "service discovery poll unchanged"
        );
    } else {
        let (from, to) = (current.addrs.len(), addrs.len());
        target.store_target_set(Arc::new(TargetSet::new(addrs, current.health.is_some())));
        tracing::info!(
            api_id = %target.api_id,
            endpoint = %cfg.endpoint,
            from,
            to,
            "service discovery updated upstream targets"
        );
        tracing::debug!(
            api_id = %target.api_id,
            targets = ?target.live_targets(),
            "discovered upstream targets"
        );
    }
    if let Some(status) = &target.discovery {
        status.record_success();
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Mutex;

    use g2_core::ApiDefinition;
    use http::{Response, StatusCode};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use super::*;

    /// Serves whatever `(status, body)` the returned handle currently holds.
    async fn spawn_json_endpoint() -> (SocketAddr, Arc<Mutex<(StatusCode, String)>>) {
        let answer = Arc::new(Mutex::new((StatusCode::OK, String::from("[]"))));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let served = Arc::clone(&answer);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let served = Arc::clone(&served);
                tokio::spawn(async move {
                    let service = service_fn(move |_req| {
                        let (status, body) = served.lock().expect("not poisoned").clone();
                        async move {
                            let mut resp =
                                Response::new(http_body_util::Full::new(bytes::Bytes::from(body)));
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
        (addr, answer)
    }

    fn discovered_target(
        endpoint: SocketAddr,
        extra: &str,
    ) -> (Arc<UpstreamTarget>, ServiceDiscoveryConfig) {
        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"sd","name":"sd","listen_path":"/sd/",
                "target_url":"http://seed.internal:1000",
                "service_discovery":{{"endpoint":"http://{endpoint}/catalog",
                    "interval_ms":20,"timeout_ms":500{extra}}}}}"#,
        ))
        .expect("def");
        let cfg = def.service_discovery.clone().expect("set");
        (Arc::new(UpstreamTarget::build(&def).expect("target")), cfg)
    }

    /// Polls until the target's live addresses equal `want` (or panics).
    async fn wait_for_targets(target: &UpstreamTarget, want: &[String]) {
        for _ in 0..400 {
            if target.live_targets() == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "targets never reached {want:?}, still {:?}",
            target.live_targets()
        );
    }

    #[tokio::test]
    async fn poll_swaps_targets_on_change_and_skips_when_unchanged() {
        let (endpoint, answer) = spawn_json_endpoint().await;
        *answer.lock().expect("lock") = (StatusCode::OK, r#"["a.internal:7001"]"#.into());
        let (target, cfg) = discovered_target(endpoint, "");

        // Seeds serve until the first successful poll lands.
        assert_eq!(target.live_targets(), ["http://seed.internal:1000"]);
        assert_eq!(
            target
                .discovery_status()
                .expect("active")
                .last_success_unix_secs,
            None
        );

        spawn_refresher(&Forwarder::new(), &target, &cfg).expect("spawned");
        wait_for_targets(&target, &["http://a.internal:7001".into()]).await;
        let status = target.discovery_status().expect("active");
        assert!(status.last_success_unix_secs.is_some());
        assert_eq!(status.last_error, None);

        // An identical poll keeps the very same set (pointer-equal: no
        // health-flag reset, no churn).
        let before = target.target_set_full();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            Arc::ptr_eq(&before, &target.target_set_full()),
            "unchanged poll replaced the target set"
        );

        // A different answer swaps again.
        *answer.lock().expect("lock") = (
            StatusCode::OK,
            r#"["a.internal:7001", "b.internal:7002"]"#.into(),
        );
        wait_for_targets(
            &target,
            &[
                "http://a.internal:7001".into(),
                "http://b.internal:7002".into(),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn failed_polls_and_empty_lists_keep_previous_targets() {
        let (endpoint, answer) = spawn_json_endpoint().await;
        *answer.lock().expect("lock") = (StatusCode::OK, r#"["a.internal"]"#.into());
        let (target, cfg) = discovered_target(endpoint, "");
        spawn_refresher(&Forwarder::new(), &target, &cfg).expect("spawned");
        wait_for_targets(&target, &["http://a.internal".into()]).await;

        for (label, broken) in [
            (
                "server error",
                (StatusCode::INTERNAL_SERVER_ERROR, String::from("boom")),
            ),
            ("garbage body", (StatusCode::OK, String::from("not json"))),
            ("empty list", (StatusCode::OK, String::from("[]"))),
            (
                "invalid entry",
                (StatusCode::OK, String::from(r#"["ftp://x"]"#)),
            ),
        ] {
            *answer.lock().expect("lock") = broken;
            // Wait until the failure is observed, then check nothing moved.
            for _ in 0..400 {
                if target
                    .discovery_status()
                    .expect("active")
                    .last_error
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let status = target.discovery_status().expect("active");
            assert!(status.last_error.is_some(), "`{label}` recorded no error");
            assert_eq!(
                target.live_targets(),
                ["http://a.internal"],
                "`{label}` changed the targets"
            );
            // Recovery clears the error without changing the set.
            *answer.lock().expect("lock") = (StatusCode::OK, r#"["a.internal"]"#.into());
            for _ in 0..400 {
                if target
                    .discovery_status()
                    .expect("active")
                    .last_error
                    .is_none()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(
                target.discovery_status().expect("active").last_error,
                None,
                "`{label}` error never cleared"
            );
        }
    }

    #[tokio::test]
    async fn refresher_exits_after_target_drop() {
        let (endpoint, _answer) = spawn_json_endpoint().await;
        let (target, cfg) = discovered_target(endpoint, "");
        let handle = spawn_refresher(&Forwarder::new(), &target, &cfg).expect("spawned");
        drop(target);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("refresher must exit once its target is dropped")
            .expect("refresher task must not panic");
    }

    #[test]
    fn entry_addr_composes_hosts_ports_and_urls() {
        let entry = |host: &str, port: Option<u16>| DiscoveredEntry {
            host: host.to_owned(),
            port,
        };
        let url = |e: &DiscoveredEntry, scheme: &str| {
            entry_addr(e, scheme).map(|a| format!("{}://{}{}", a.scheme, a.authority, a.base_path))
        };

        assert_eq!(
            url(&entry("a.internal", None), "http").as_deref(),
            Ok("http://a.internal")
        );
        assert_eq!(
            url(&entry("a.internal", Some(9000)), "https").as_deref(),
            Ok("https://a.internal:9000")
        );
        // An entry's own port wins over the resolved one.
        assert_eq!(
            url(&entry("a.internal:7000", Some(9000)), "http").as_deref(),
            Ok("http://a.internal:7000")
        );
        assert_eq!(
            url(&entry("[::1]", Some(9000)), "http").as_deref(),
            Ok("http://[::1]:9000")
        );
        // Full URLs pass through, keeping scheme/port/base path.
        assert_eq!(
            url(&entry("https://b.internal:8443/base/", Some(9000)), "http").as_deref(),
            Ok("https://b.internal:8443/base")
        );
        assert!(url(&entry("ftp://x.internal", None), "http").is_err());
        assert!(url(&entry("not a host", None), "http").is_err());
    }
}
