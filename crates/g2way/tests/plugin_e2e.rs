//! End-to-end WASM plugin tests: a real g2way server running guest modules
//! (compiled from WAT at test time) as pre/post hooks in front of a fake
//! upstream over TCP (milestone M8+, ADR-0005).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use g2_core::ApiDefinition;
use g2_middleware::SharedPluginLoader;
use g2_plugin::PluginHost;
use g2_proxy::{Forwarder, Gateway, RouteResources, RouteTable};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Spawns a fake upstream that echoes the request headers it saw back as a
/// JSON object, counting hits.
async fn spawn_echo_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_in = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits_in);
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let headers: serde_json::Map<String, serde_json::Value> = req
                            .headers()
                            .iter()
                            .map(|(name, value)| {
                                (
                                    name.as_str().to_owned(),
                                    serde_json::Value::from(String::from_utf8_lossy(
                                        value.as_bytes(),
                                    )),
                                )
                            })
                            .collect();
                        let reply = serde_json::json!({ "headers": headers }).to_string();
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            reply,
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, hits)
}

/// Compiles each `(file, wat)` guest into `dir` for the gateway to load.
fn install_plugins(dir: &std::path::Path, plugins: &[(&str, &str)]) {
    for (file, wat_text) in plugins {
        let wasm = wat::parse_str(wat_text).expect("valid WAT");
        std::fs::write(dir.join(file), wasm).expect("write module");
    }
}

/// Starts a full g2way server for `defs` with a real [`PluginHost`] over
/// `plugins_dir`; returns its address and a shutdown trigger.
async fn spawn_gateway(
    defs: Vec<ApiDefinition>,
    plugins_dir: &std::path::Path,
) -> (SocketAddr, oneshot::Sender<()>) {
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let loader: SharedPluginLoader = Arc::new(PluginHost::new(plugins_dir).expect("plugin host"));
    let forwarder = Forwarder::new();
    let table = RouteTable::build(
        defs,
        &RouteResources {
            plugin_loader: Some(&loader),
            ..RouteResources::new(&forwarder, &storage)
        },
    )
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

/// A keyless API definition with the given `plugins` block.
fn api_with_plugins(target: &str, plugins: serde_json::Value) -> ApiDefinition {
    let mut def = serde_json::json!({
        "api_id": "plugin-e2e",
        "name": "plugin-e2e",
        "listen_path": "/p/",
        "target_url": target,
        "auth": { "mode": "keyless" }
    });
    if !plugins.is_null() {
        def["plugins"] = plugins;
    }
    serde_json::from_str(&def.to_string()).expect("definition")
}

/// A guest that ignores its input and returns `output` verbatim.
fn static_guest(output: &str) -> String {
    let escaped = output.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"(module
          (memory (export "memory") 4)
          (func (export "g2_abi_version") (result i32) i32.const 1)
          (func (export "g2_alloc") (param i32) (result i32) i32.const 65536)
          (data (i32.const 0) "{escaped}")
          (func (export "g2_hook") (param i32 i32) (result i64)
            i64.const {len}))
        "#,
        len = output.len(),
    )
}

async fn send(gw: SocketAddr, path: &str) -> (StatusCode, String) {
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .uri(format!("http://{gw}{path}"))
        .header("x-internal", "secret")
        .body(Empty::new())
        .expect("request");
    let resp = client.request(req).await.expect("response");
    let status = resp.status();
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn apis_without_plugins_are_untouched() {
    let (upstream, _hits) = spawn_echo_upstream().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let def = api_with_plugins(&format!("http://{upstream}"), serde_json::Value::Null);
    let (gw, _stop) = spawn_gateway(vec![def], dir.path()).await;

    let (status, body) = send(gw, "/p/echo").await;
    assert_eq!(status, StatusCode::OK);
    let seen: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(seen["headers"]["x-internal"], "secret");
    assert_eq!(seen["headers"]["x-from-plugin"], serde_json::Value::Null);
}

#[tokio::test]
async fn pre_plugin_mutations_reach_the_upstream() {
    let (upstream, _hits) = spawn_echo_upstream().await;
    let dir = tempfile::tempdir().expect("tempdir");
    install_plugins(
        dir.path(),
        &[(
            "mutate.wasm",
            &static_guest(
                r#"{"action":"continue","set_headers":[["x-from-plugin","yes"]],"remove_headers":["x-internal"]}"#,
            ),
        )],
    );
    let def = api_with_plugins(
        &format!("http://{upstream}"),
        serde_json::json!({"pre": [{"name": "mutate", "path": "mutate.wasm"}]}),
    );
    let (gw, _stop) = spawn_gateway(vec![def], dir.path()).await;

    let (status, body) = send(gw, "/p/echo").await;
    assert_eq!(status, StatusCode::OK);
    let seen: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(seen["headers"]["x-from-plugin"], "yes");
    assert_eq!(
        seen["headers"]["x-internal"],
        serde_json::Value::Null,
        "removed header must not reach the upstream"
    );
}

#[tokio::test]
async fn short_circuit_plugin_answers_without_the_upstream() {
    let (upstream, hits) = spawn_echo_upstream().await;
    let dir = tempfile::tempdir().expect("tempdir");
    install_plugins(
        dir.path(),
        &[(
            "deny.wasm",
            &static_guest(
                r#"{"action":"respond","response":{"status":403,"headers":[["content-type","text/plain"]],"body":"denied by plugin"}}"#,
            ),
        )],
    );
    let def = api_with_plugins(
        &format!("http://{upstream}"),
        serde_json::json!({"pre": [{"name": "deny", "path": "deny.wasm"}]}),
    );
    let (gw, _stop) = spawn_gateway(vec![def], dir.path()).await;

    let (status, body) = send(gw, "/p/anything").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "denied by plugin");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "upstream must not be hit");
}

#[tokio::test]
async fn pre_hooks_run_before_auth_and_post_hooks_after() {
    let (upstream, _hits) = spawn_echo_upstream().await;
    let dir = tempfile::tempdir().expect("tempdir");
    install_plugins(
        dir.path(),
        &[(
            "teapot.wasm",
            &static_guest(r#"{"action":"respond","response":{"status":418}}"#),
        )],
    );
    // Token auth over empty storage: every request is otherwise a 401.
    let mut def = api_with_plugins(
        &format!("http://{upstream}"),
        serde_json::json!({"pre": [{"name": "teapot", "path": "teapot.wasm"}]}),
    );
    def.auth = serde_json::from_str(r#"{"mode":"auth_token"}"#).expect("auth");
    let (gw, _stop) = spawn_gateway(vec![def], dir.path()).await;
    let (status, _) = send(gw, "/p/x").await;
    assert_eq!(
        status,
        StatusCode::IM_A_TEAPOT,
        "a pre hook answers before auth rejects"
    );

    let mut def = api_with_plugins(
        &format!("http://{upstream}"),
        serde_json::json!({"post": [{"name": "teapot", "path": "teapot.wasm"}]}),
    );
    def.auth = serde_json::from_str(r#"{"mode":"auth_token"}"#).expect("auth");
    let (gw, _stop) = spawn_gateway(vec![def], dir.path()).await;
    let (status, _) = send(gw, "/p/x").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a post hook never runs on an unauthenticated request"
    );
}

#[tokio::test]
async fn plugins_run_in_declared_order() {
    let (upstream, _hits) = spawn_echo_upstream().await;
    let dir = tempfile::tempdir().expect("tempdir");
    install_plugins(
        dir.path(),
        &[
            (
                "first.wasm",
                &static_guest(r#"{"action":"continue","set_headers":[["x-order","first"]]}"#),
            ),
            (
                "second.wasm",
                &static_guest(r#"{"action":"continue","set_headers":[["x-order","second"]]}"#),
            ),
        ],
    );
    let def = api_with_plugins(
        &format!("http://{upstream}"),
        serde_json::json!({"pre": [
            {"name": "first", "path": "first.wasm"},
            {"name": "second", "path": "second.wasm"}
        ]}),
    );
    let (gw, _stop) = spawn_gateway(vec![def], dir.path()).await;

    let (status, body) = send(gw, "/p/echo").await;
    assert_eq!(status, StatusCode::OK);
    let seen: serde_json::Value = serde_json::from_str(&body).expect("json");
    // Insert semantics: the later plugin's value replaces the earlier one's.
    assert_eq!(seen["headers"]["x-order"], "second");
}

/// Keeps `examples/plugins/header_tag.wat` honest: the shipped example must
/// compile and behave exactly as its comments (and docs/plugins.md) claim.
#[tokio::test]
async fn shipped_example_plugin_works() {
    let (upstream, _hits) = spawn_echo_upstream().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let wat_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/plugins/header_tag.wat");
    let wasm = wat::parse_file(&wat_path).expect("example WAT compiles");
    std::fs::write(dir.path().join("header_tag.wasm"), wasm).expect("write module");

    let def = api_with_plugins(
        &format!("http://{upstream}"),
        serde_json::json!({"pre": [{"name": "header-tag", "path": "header_tag.wasm"}]}),
    );
    let (gw, _stop) = spawn_gateway(vec![def], dir.path()).await;

    let (status, body) = send(gw, "/p/echo").await;
    assert_eq!(status, StatusCode::OK);
    let seen: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(seen["headers"]["x-from-plugin"], "yes");
    assert_eq!(seen["headers"]["x-internal"], serde_json::Value::Null);
}

#[tokio::test]
async fn broken_plugin_fails_the_route_build() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("garbage.wasm"), b"not wasm").expect("write");
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let loader: SharedPluginLoader = Arc::new(PluginHost::new(dir.path()).expect("plugin host"));
    let forwarder = Forwarder::new();

    for path in ["garbage.wasm", "missing.wasm"] {
        let def = api_with_plugins(
            "http://unused.internal",
            serde_json::json!({"pre": [{"name": "broken", "path": path}]}),
        );
        let err = RouteTable::build(
            vec![def],
            &RouteResources {
                plugin_loader: Some(&loader),
                ..RouteResources::new(&forwarder, &storage)
            },
        )
        .expect_err("a broken plugin must fail the build");
        assert!(
            err.to_string().contains("failed to load"),
            "path {path}: {err}"
        );
    }
}
