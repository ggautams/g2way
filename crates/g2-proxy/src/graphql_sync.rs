//! GraphQL schema-sync refresher: periodic upstream introspection with
//! live schema swaps (milestone M9, ADR-0008).
//!
//! An API with `graphql.schema_sync` gets one refresher task per forwarding
//! [`UpstreamTarget`] (spawned at route-build time, like health checking
//! and service discovery). The task POSTs
//! [`g2_middleware::INTROSPECTION_QUERY`] to the API's upstream —
//! immediately once, then every interval, plus whenever an admin nudge
//! [`trigger`](g2_middleware::GraphQlSyncHandle::trigger)s it — and hands
//! the response to
//! [`apply_introspection`](g2_middleware::GraphQlSyncHandle::apply_introspection),
//! which swaps the layer's compiled schema on change (stale-on-error: any
//! failure keeps the previous schema serving and is surfaced on
//! `GET /g2/node`).
//!
//! The introspection request speaks the upstream's protocol
//! ([`Forwarder::client_for`], like health probes) and follows load
//! balancing, service discovery, and health eviction by deriving its URL
//! from [`TargetSet::next_addr`](crate::forward::TargetSet) per fetch —
//! unless `schema_sync.url` pins an explicit endpoint, which then rides the
//! HTTP/1.1 pool like JWKS and discovery fetches.
//!
//! Lifecycle: the task holds only weak references (target + layer state),
//! so a config reload that drops the old route table ends it on its next
//! wakeup; while waiting it holds nothing but a detached nudge listener.

use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use g2_middleware::{GraphQlSyncHandle, ProxyBody, WeakGraphQlSync, INTROSPECTION_QUERY};
use http::header::{HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE};
use http::{Method, Request, Uri};

use crate::forward::{Forwarder, UpstreamAddr, UpstreamClient, UpstreamTarget};

/// Largest introspection response body accepted. Larger than the discovery
/// and JWKS caps because big schemas legitimately introspect to megabytes.
const MAX_INTROSPECTION_BYTES: usize = 4 * 1024 * 1024;

/// The precomputed, per-fetch-invariant parts of the introspection request.
struct SyncRequest {
    /// The pinned endpoint from `schema_sync.url`; `None` derives the URL
    /// from the target's current address per fetch.
    fixed_uri: Option<Uri>,
    /// Extra request headers from `schema_sync.headers`.
    headers: Vec<(HeaderName, HeaderValue)>,
    /// The JSON request body (`{"query": INTROSPECTION_QUERY}`).
    body: Bytes,
    timeout: Duration,
}

/// Spawns the sync loop for `target`, driven through `handle`.
///
/// Returns the task handle, or `None` when no tokio runtime is running
/// (synchronous route builds in tests — the binary always builds tables
/// inside the runtime) or the validated config unexpectedly fails to
/// precompile.
pub(crate) fn spawn_refresher(
    forwarder: &Forwarder,
    target: &Arc<UpstreamTarget>,
    handle: &GraphQlSyncHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            api_id = handle.api_id(),
            "no tokio runtime available; graphql schema sync stays disabled"
        );
        return None;
    };
    let cfg = handle.config();
    // All parts below are pre-validated with the definition; a failure here
    // means a definition skipped validation — disable sync loudly rather
    // than panic (the from_config convention).
    let fixed_uri = match &cfg.url {
        Some(url) => match url.parse::<Uri>() {
            Ok(uri) => Some(uri),
            Err(error) => {
                tracing::warn!(
                    api_id = handle.api_id(),
                    url,
                    %error,
                    "invalid `schema_sync.url`; graphql schema sync stays disabled"
                );
                return None;
            }
        },
        None => None,
    };
    let mut headers = Vec::with_capacity(cfg.headers.len());
    for (name, value) in &cfg.headers {
        match (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            (Ok(name), Ok(value)) => headers.push((name, value)),
            _ => {
                tracing::warn!(
                    api_id = handle.api_id(),
                    header = name,
                    "invalid `schema_sync.headers` entry; graphql schema sync stays disabled"
                );
                return None;
            }
        }
    }
    let request = SyncRequest {
        fixed_uri,
        headers,
        body: Bytes::from(serde_json::json!({ "query": INTROSPECTION_QUERY }).to_string()),
        timeout: Duration::from_millis(cfg.timeout_ms),
    };
    // A pinned URL is an ordinary JSON-over-HTTP side channel (HTTP/1.1
    // pool, like JWKS/discovery); the API's own upstream is spoken to in
    // its protocol, like health probes.
    let client = match &request.fixed_uri {
        Some(_) => forwarder.client().clone(),
        None => forwarder.client_for(target).clone(),
    };
    let interval = Duration::from_millis(cfg.interval_ms);
    Some(runtime.spawn(run_refresher(
        client,
        Arc::downgrade(target),
        handle.downgrade(),
        handle.nudge(),
        request,
        interval,
    )))
}

/// The sync task: fetches immediately (the seed schema serves until the
/// first success), then on every interval tick or admin nudge, until the
/// target or the layer state is dropped (route table swap).
async fn run_refresher(
    client: UpstreamClient,
    target: Weak<UpstreamTarget>,
    sync: WeakGraphQlSync,
    nudge: g2_middleware::SyncNudge,
    request: SyncRequest,
    interval: Duration,
) {
    loop {
        if !sync_once(&client, &target, &sync, &request).await {
            return;
        }
        nudge.wait_interval(interval).await;
    }
}

/// One sync cycle: fetch, convert, swap-on-change. Returns `false` once the
/// target or layer state is gone and the task should end.
async fn sync_once(
    client: &UpstreamClient,
    target: &Weak<UpstreamTarget>,
    sync: &WeakGraphQlSync,
    request: &SyncRequest,
) -> bool {
    let Some(target) = target.upgrade() else {
        return false;
    };
    let Some(handle) = sync.upgrade() else {
        return false;
    };
    match fetch_and_apply(client, &target, &handle, request).await {
        Ok(true) => {
            tracing::info!(
                api_id = handle.api_id(),
                "graphql schema updated from upstream introspection"
            );
        }
        Ok(false) => {
            tracing::debug!(api_id = handle.api_id(), "graphql schema sync unchanged");
        }
        Err(error) => {
            tracing::warn!(
                api_id = handle.api_id(),
                %error,
                "graphql schema sync failed; keeping previous schema"
            );
            handle.record_error(error);
        }
    }
    true
}

/// Fetches one introspection response and applies it. `Ok(true)` = the
/// schema was swapped; `Ok(false)` = unchanged.
async fn fetch_and_apply(
    client: &UpstreamClient,
    target: &UpstreamTarget,
    handle: &GraphQlSyncHandle,
    request: &SyncRequest,
) -> Result<bool, String> {
    let uri = match &request.fixed_uri {
        Some(uri) => uri.clone(),
        // Derived per fetch, so LB rotation, discovery swaps, and health
        // eviction all steer introspection like they steer traffic. The
        // guard is dropped before any await (hot-path leaf rule).
        None => introspection_uri(target.target_set().next_addr(target.cursor())),
    };
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json");
    for (name, value) in &request.headers {
        builder = builder.header(name.clone(), value.clone());
    }
    let req = builder
        .body(ProxyBody::new(http_body_util::Full::new(
            request.body.clone(),
        )))
        .map_err(|e| format!("could not build introspection request: {e}"))?;
    let resp = tokio::time::timeout(request.timeout, client.request(req))
        .await
        .map_err(|_| format!("introspection timed out after {:?}", request.timeout))?
        .map_err(|e| format!("introspection request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("introspection endpoint answered {}", resp.status()));
    }
    let body = http_body_util::Limited::new(resp.into_body(), MAX_INTROSPECTION_BYTES);
    let collected = http_body_util::BodyExt::collect(body)
        .await
        .map_err(|e| format!("reading introspection body failed: {e}"))?;
    let doc: serde_json::Value = serde_json::from_slice(&collected.to_bytes())
        .map_err(|e| format!("introspection response is not JSON: {e}"))?;
    handle.apply_introspection(&doc)
}

/// The introspection URL for one upstream address: its base path (the
/// upstream GraphQL endpoint the proxy forwards to), `/` when empty.
fn introspection_uri(addr: &UpstreamAddr) -> Uri {
    let path = if addr.base_path.is_empty() {
        "/"
    } else {
        addr.base_path.as_str()
    };
    Uri::builder()
        .scheme(addr.scheme.clone())
        .authority(addr.authority.clone())
        .path_and_query(path)
        .build()
        .expect("validated target parts form a URI")
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use g2_core::ApiDefinition;
    use g2_middleware::GraphQlLayer;
    use http::{HeaderMap, Response, StatusCode};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use super::*;

    /// Introspection JSON for `type Query { hello: String }`.
    const HELLO_ONLY: &str = r#"{"data":{"__schema":{
        "queryType":{"name":"Query"},
        "types":[
            {"kind":"OBJECT","name":"Query","fields":[
                {"name":"hello","args":[],"type":{"kind":"SCALAR","name":"String"}}]},
            {"kind":"SCALAR","name":"String"}
        ]}}}"#;

    /// Introspection JSON for `type Query { hello: String extra: Int }`.
    const WITH_EXTRA: &str = r#"{"data":{"__schema":{
        "queryType":{"name":"Query"},
        "types":[
            {"kind":"OBJECT","name":"Query","fields":[
                {"name":"hello","args":[],"type":{"kind":"SCALAR","name":"String"}},
                {"name":"extra","args":[],"type":{"kind":"SCALAR","name":"Int"}}]},
            {"kind":"SCALAR","name":"String"},
            {"kind":"SCALAR","name":"Int"}
        ]}}}"#;

    /// State the fake upstream shares with the test: the served answer plus
    /// what it observed.
    struct Endpoint {
        answer: Mutex<(StatusCode, String)>,
        hits: AtomicUsize,
        last_request: Mutex<Option<(String, HeaderMap)>>,
    }

    async fn spawn_introspection_endpoint() -> (SocketAddr, Arc<Endpoint>) {
        let endpoint = Arc::new(Endpoint {
            answer: Mutex::new((StatusCode::OK, HELLO_ONLY.to_owned())),
            hits: AtomicUsize::new(0),
            last_request: Mutex::new(None),
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let served = Arc::clone(&endpoint);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let served = Arc::clone(&served);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                        served.hits.fetch_add(1, Ordering::SeqCst);
                        *served.last_request.lock().expect("not poisoned") =
                            Some((req.uri().path().to_owned(), req.headers().clone()));
                        let (status, body) = served.answer.lock().expect("not poisoned").clone();
                        async move {
                            let mut resp =
                                Response::new(http_body_util::Full::new(Bytes::from(body)));
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
        (addr, endpoint)
    }

    /// A synced GraphQL definition targeting `upstream` with `sync_extra`
    /// spliced into the `schema_sync` object.
    fn synced_parts(
        upstream: SocketAddr,
        sync_extra: &str,
    ) -> (Arc<UpstreamTarget>, GraphQlLayer, GraphQlSyncHandle) {
        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"gql","name":"gql","listen_path":"/gql/",
                "target_url":"http://{upstream}/graphql",
                "auth":{{"mode":"keyless"}},
                "graphql":{{
                    "schema":"type Query {{ hello: String }}",
                    "schema_sync":{{"timeout_ms":500{sync_extra}}}
                }}}}"#,
        ))
        .expect("def");
        def.validate().expect("valid def");
        let target = Arc::new(UpstreamTarget::build(&def).expect("target"));
        let layer = GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def, None)
            .expect("compiles")
            .expect("enabled");
        let handle = layer.sync_handle().expect("sync configured");
        (target, layer, handle)
    }

    /// Polls until `check` on the handle's status returns true (or panics).
    async fn wait_for_status(
        handle: &GraphQlSyncHandle,
        label: &str,
        check: impl Fn(&g2_middleware::SchemaSyncSnapshot) -> bool,
    ) {
        for _ in 0..400 {
            if check(&handle.status()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("`{label}` never observed, status {:?}", handle.status());
    }

    #[tokio::test]
    async fn first_fetch_syncs_and_failures_go_stale() {
        let (upstream, endpoint) = spawn_introspection_endpoint().await;
        let (target, _layer, handle) = synced_parts(upstream, r#","interval_ms":20"#);

        spawn_refresher(&Forwarder::new(), &target, &handle).expect("spawned");
        wait_for_status(&handle, "first success", |s| {
            s.last_success_unix_secs.is_some()
        })
        .await;
        // The fetch went to the upstream's base path with the right shape.
        let (path, headers) = endpoint
            .last_request
            .lock()
            .expect("lock")
            .clone()
            .expect("a request arrived");
        assert_eq!(path, "/graphql");
        assert_eq!(
            headers.get(CONTENT_TYPE).map(|v| v.as_bytes()),
            Some(b"application/json".as_ref())
        );

        // A failing endpoint records the error and keeps the schema.
        *endpoint.answer.lock().expect("lock") = (StatusCode::INTERNAL_SERVER_ERROR, "boom".into());
        wait_for_status(&handle, "error recorded", |s| s.last_error.is_some()).await;

        // Recovery clears it.
        *endpoint.answer.lock().expect("lock") = (StatusCode::OK, WITH_EXTRA.to_owned());
        wait_for_status(&handle, "error cleared", |s| s.last_error.is_none()).await;
    }

    #[tokio::test]
    async fn trigger_prompts_an_immediate_refetch() {
        let (upstream, endpoint) = spawn_introspection_endpoint().await;
        let (target, _layer, handle) = synced_parts(upstream, r#","interval_ms":3600000"#);

        spawn_refresher(&Forwarder::new(), &target, &handle).expect("spawned");
        wait_for_status(&handle, "first success", |s| {
            s.last_success_unix_secs.is_some()
        })
        .await;
        let after_first = endpoint.hits.load(Ordering::SeqCst);

        // With an hour-long interval, only a trigger explains a second hit.
        handle.trigger();
        for _ in 0..400 {
            if endpoint.hits.load(Ordering::SeqCst) > after_first {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("trigger caused no refetch");
    }

    #[tokio::test]
    async fn url_override_and_headers_reach_the_endpoint() {
        let (side_channel, endpoint) = spawn_introspection_endpoint().await;
        // The API's own target points nowhere routable; the pinned URL must
        // be fetched instead.
        let (target, _layer, handle) = synced_parts(
            "192.0.2.1:1".parse().expect("addr"),
            &format!(
                r#","interval_ms":20,"url":"http://{side_channel}/introspect","headers":{{"x-sync-auth":"s3cr3t"}}"#
            ),
        );

        spawn_refresher(&Forwarder::new(), &target, &handle).expect("spawned");
        wait_for_status(&handle, "success via url override", |s| {
            s.last_success_unix_secs.is_some()
        })
        .await;
        let (path, headers) = endpoint
            .last_request
            .lock()
            .expect("lock")
            .clone()
            .expect("a request arrived");
        assert_eq!(path, "/introspect");
        assert_eq!(
            headers.get("x-sync-auth").map(|v| v.as_bytes()),
            Some(b"s3cr3t".as_ref())
        );
    }

    #[tokio::test]
    async fn refresher_exits_after_state_drop() {
        let (upstream, _endpoint) = spawn_introspection_endpoint().await;
        let (target, layer, handle) = synced_parts(upstream, r#","interval_ms":20"#);
        let task = spawn_refresher(&Forwarder::new(), &target, &handle).expect("spawned");
        drop((target, layer, handle));
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("refresher must exit once its state is dropped")
            .expect("refresher task must not panic");
    }

    #[test]
    fn introspection_uri_joins_the_base_path() {
        let addr = UpstreamAddr {
            scheme: http::uri::Scheme::HTTP,
            authority: "gql.internal:4000".parse().expect("authority"),
            base_path: "/graphql".into(),
        };
        assert_eq!(
            introspection_uri(&addr).to_string(),
            "http://gql.internal:4000/graphql"
        );
        let bare = UpstreamAddr {
            base_path: String::new(),
            ..addr
        };
        assert_eq!(
            introspection_uri(&bare).to_string(),
            "http://gql.internal:4000/"
        );
    }
}
