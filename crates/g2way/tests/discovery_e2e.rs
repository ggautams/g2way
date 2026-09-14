//! End-to-end service-discovery tests: a real g2way server whose upstream
//! targets are live-swapped by polling a real (in-process) discovery
//! endpoint — no reloads, no external services.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use g2_core::ApiDefinition;
use g2_proxy::{Forwarder, Gateway, RouteResources, RouteTable};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Spawns an HTTP/1.1 upstream answering every request with `name`.
async fn spawn_named_upstream(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                        name.as_bytes(),
                    ))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

/// Spawns a discovery endpoint serving whatever JSON the handle currently
/// holds; aborting the returned task kills the endpoint (polls then fail).
async fn spawn_discovery_endpoint() -> (SocketAddr, Arc<Mutex<String>>, tokio::task::JoinHandle<()>)
{
    let body = Arc::new(Mutex::new(String::from("[]")));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind discovery endpoint");
    let addr = listener.local_addr().expect("endpoint addr");
    let served = Arc::clone(&body);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let json = served.lock().expect("not poisoned").clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            json,
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, body, task)
}

/// A keyless definition polling `endpoint` for its targets, seeded on `seed`.
fn discovered_api(seed: SocketAddr, endpoint: SocketAddr) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"sd-e2e","name":"sd","listen_path":"/svc/",
            "target_url":"http://{seed}","auth":{{"mode":"keyless"}},
            "service_discovery":{{"endpoint":"http://{endpoint}/services",
                "interval_ms":25,"timeout_ms":500}}}}"#
    ))
    .expect("definition")
}

/// Starts a full g2way server for `defs`; returns its address and a shutdown
/// trigger.
async fn spawn_gateway(defs: Vec<ApiDefinition>) -> (SocketAddr, oneshot::Sender<()>) {
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let table = RouteTable::build(defs, &RouteResources::new(&Forwarder::new(), &storage))
        .expect("route table");
    let gateway = Arc::new(Gateway::new(table));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        g2way::server::serve(
            listener,
            gateway,
            async {
                let _ = rx.await;
            },
            Duration::from_secs(5),
        )
        .await
        .expect("serve");
    });
    (addr, tx)
}

async fn http_get(url: &str) -> (StatusCode, String) {
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(url.parse().expect("url"))
        .await
        .expect("request");
    let status = resp.status();
    let body = resp.collect().await.expect("body").to_bytes();
    (status, String::from_utf8(body.to_vec()).expect("utf8"))
}

/// Polls the gateway until it answers `200` with `want` (or panics).
async fn wait_for_body(url: &str, want: &str) {
    let mut last = (StatusCode::IM_A_TEAPOT, String::new());
    for _ in 0..400 {
        last = http_get(url).await;
        if last.0 == StatusCode::OK && last.1 == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("gateway never answered `{want}`, last: {last:?}");
}

#[tokio::test]
async fn traffic_follows_discovery_swaps_without_a_reload() {
    let a = spawn_named_upstream("upstream-a").await;
    let b = spawn_named_upstream("upstream-b").await;
    let (endpoint, catalog, _task) = spawn_discovery_endpoint().await;
    *catalog.lock().expect("lock") = format!(r#"["{a}"]"#);

    // Seeded on A, and the first poll also resolves A: traffic reaches A.
    let (gw, _stop) = spawn_gateway(vec![discovered_api(a, endpoint)]).await;
    let url = format!("http://{gw}/svc/hello");
    wait_for_body(&url, "upstream-a").await;

    // The catalog flips to B; within an interval the gateway follows,
    // with no reload and no restart.
    *catalog.lock().expect("lock") = format!(r#"["{b}"]"#);
    wait_for_body(&url, "upstream-b").await;

    // And back.
    *catalog.lock().expect("lock") = format!(r#"["{a}"]"#);
    wait_for_body(&url, "upstream-a").await;
}

#[tokio::test]
async fn discovered_targets_survive_a_dead_discovery_endpoint() {
    let a = spawn_named_upstream("upstream-a").await;
    let b = spawn_named_upstream("upstream-b").await;
    let (endpoint, catalog, endpoint_task) = spawn_discovery_endpoint().await;
    *catalog.lock().expect("lock") = format!(r#"["{b}"]"#);

    // Seeded on A, but discovery resolves B before long.
    let (gw, _stop) = spawn_gateway(vec![discovered_api(a, endpoint)]).await;
    let url = format!("http://{gw}/svc/hello");
    wait_for_body(&url, "upstream-b").await;

    // The discovery endpoint dies. Polls now fail (connection refused), and
    // stale-on-error keeps the last resolved target serving.
    endpoint_task.abort();
    tokio::time::sleep(Duration::from_millis(150)).await;
    for _ in 0..3 {
        let (status, body) = http_get(&url).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "upstream-b", "stale targets must keep serving");
    }
}
