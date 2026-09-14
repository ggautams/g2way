//! Admin/control-plane API for g2way.
//!
//! An [`axum`] application served on its **own listener** (see
//! `admin_listen_addr` in [`g2_core::GatewayConfig`]), so deployments can
//! keep it off the public network while the proxy listener stays exposed.
//!
//! Every endpoint under `/g2/` except `/g2/health` requires the configured
//! admin secret in the [`ADMIN_AUTH_HEADER`] (`X-G2-Authorization`)
//! header. Requests with a missing or wrong
//! secret get a single `403` message (no oracle), and unmatched paths are
//! only revealed as `404` to authenticated callers.
//!
//! Endpoints: `/g2/health` (liveness, unauthenticated), `/metrics`
//! (Prometheus text exposition, unauthenticated — scrapers do not send
//! custom headers; keep the admin port off the public network), `/g2/version`
//! (authenticated), key CRUD under `/g2/keys` (authenticated; raw keys
//! are returned only at creation — storage holds hashes, see
//! [`g2_core::session::hash_key`]), API definition / policy CRUD under
//! `/g2/apis` and `/g2/policies` (authenticated; definition changes go
//! live on reload, not on write), `POST /g2/reload` (authenticated) —
//! broadcasts a reload nudge over storage pub/sub so every pod rebuilds
//! its route table from the current files + storage — and the
//! dashboard-support pair `GET /g2/node` / `GET /g2/stats`
//! (authenticated; see [`Dashboard`]).

mod dashboard;
mod keys;
mod openapi;
mod resources;

pub use dashboard::Dashboard;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use g2_core::Error;
use g2_storage::SharedStorage;
use sha2::{Digest, Sha256};

/// Header carrying the admin secret, checked on every authenticated route.
pub const ADMIN_AUTH_HEADER: &str = "x-g2-authorization";

/// Single message for missing and wrong secrets alike: which one it was
/// must not leak to the caller.
const FORBIDDEN_MSG: &str = "admin authorization missing or invalid";

/// Shared state for the admin router.
#[derive(Clone)]
struct AdminState {
    /// SHA-256 of the configured admin secret. Comparing digests (instead
    /// of the raw strings) keeps comparison timing independent of how much
    /// of the secret a caller guessed correctly.
    secret_digest: [u8; 32],

    /// The same storage backend the gateway authenticates against.
    storage: SharedStorage,

    /// Live-gateway handles for the dashboard endpoints; `None` when the
    /// router is built without them (those endpoints then answer 503).
    dashboard: Option<Dashboard>,

    /// Prometheus render handle for `GET /metrics`; `None` when metrics
    /// are not enabled (the endpoint then answers 503).
    metrics: Option<g2_telemetry::PrometheusHandle>,
}

impl AdminState {
    fn secret_matches(&self, presented: &str) -> bool {
        let presented: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        presented == self.secret_digest
    }
}

/// Builds the admin API router, gated by `admin_secret`, operating on the
/// same `storage` the gateway authenticates against.
///
/// # Errors
///
/// Returns [`Error::InvalidGatewayConfig`] when `admin_secret` is empty:
/// the admin API never runs unsecured. (The binary also enforces this via
/// [`g2_core::GatewayConfig::validate`]; this is defense in depth for other
/// callers.)
pub fn router(
    admin_secret: &str,
    storage: SharedStorage,
    dashboard: Option<Dashboard>,
    metrics: Option<g2_telemetry::PrometheusHandle>,
) -> Result<Router, Error> {
    if admin_secret.trim().is_empty() {
        return Err(Error::InvalidGatewayConfig {
            reason: "admin secret must not be empty".into(),
        });
    }
    let state = AdminState {
        secret_digest: Sha256::digest(admin_secret.as_bytes()).into(),
        storage,
        dashboard,
        metrics,
    };

    // The fallback lives inside the authed router so unknown paths are
    // only distinguishable from known ones by authenticated callers.
    let authed = Router::new()
        .route("/g2/version", get(version))
        .route("/g2/reload", post(reload))
        .route("/g2/node", get(dashboard::node))
        .route("/g2/stats", get(dashboard::stats))
        .route("/g2/keys", get(keys::list_keys).post(keys::create_key))
        .route(
            "/g2/keys/{key}",
            get(keys::get_key)
                .put(keys::put_key)
                .delete(keys::delete_key),
        )
        .route(
            "/g2/apis",
            get(resources::list_apis).post(resources::create_api),
        )
        .route(
            "/g2/apis/{id}",
            get(resources::get_api)
                .put(resources::put_api)
                .delete(resources::delete_api),
        )
        .route(
            "/g2/policies",
            get(resources::list_policies).post(resources::create_policy),
        )
        .route(
            "/g2/policies/{id}",
            get(resources::get_policy)
                .put(resources::put_policy)
                .delete(resources::delete_policy),
        )
        .route("/g2/openapi.json", get(openapi::spec))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_secret,
        ))
        .with_state(state.clone());

    Ok(Router::new()
        .route("/g2/health", get(health))
        .route("/metrics", get(prometheus_metrics))
        .with_state(state)
        .merge(authed))
}

/// Serves `router` on `listener` until `shutdown` resolves, then drains.
///
/// # Errors
///
/// Returns an error only if accepting on `listener` fails fatally.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

/// Middleware rejecting any request whose [`ADMIN_AUTH_HEADER`] does not
/// match the configured secret.
async fn require_admin_secret(
    State(state): State<AdminState>,
    req: Request,
    next: Next,
) -> Response {
    let presented = req
        .headers()
        .get(ADMIN_AUTH_HEADER)
        .and_then(|v| v.to_str().ok());
    match presented {
        Some(secret) if state.secret_matches(secret) => next.run(req).await,
        _ => {
            tracing::warn!("admin request rejected: missing or wrong secret");
            error_response(StatusCode::FORBIDDEN, FORBIDDEN_MSG)
        }
    }
}

/// `GET /g2/health` — unauthenticated liveness for probes on the admin port.
#[utoipa::path(get, path = "/g2/health", tag = "system",
    responses((status = 200, description = "Node is alive: `{\"status\":\"pass\"}`")))]
async fn health() -> Response {
    Json(serde_json::json!({ "status": "pass" })).into_response()
}

/// `GET /metrics` — the gateway's metrics in the Prometheus text exposition
/// format (unauthenticated: scrapers do not send custom headers, and the
/// admin port is expected to stay off the public network).
#[utoipa::path(get, path = "/metrics", tag = "system",
    responses(
        (status = 200, description = "Prometheus text exposition of the gateway's metrics",
            content_type = "text/plain"),
        (status = 503, description = "Metrics are not enabled on this node"),
    ))]
async fn prometheus_metrics(State(state): State<AdminState>) -> Response {
    match &state.metrics {
        Some(handle) => (
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4",
            )],
            handle.render(),
        )
            .into_response(),
        None => error_response(StatusCode::SERVICE_UNAVAILABLE, "metrics not enabled"),
    }
}

/// `GET /g2/version` — the gateway's version (workspace-wide, so the crate
/// version equals the binary's).
#[utoipa::path(get, path = "/g2/version", tag = "system",
    security(("admin_secret" = [])),
    responses(
        (status = 200, description = "Gateway version: `{\"version\":…}`"),
        (status = 403, description = "Admin secret missing or wrong"),
    ))]
async fn version() -> Response {
    Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") })).into_response()
}

/// `POST /g2/reload` — broadcast a config-reload nudge to every gateway
/// pod (this one included) via storage pub/sub.
///
/// Returns as soon as the nudge is published: reloads happen
/// asynchronously on each pod, which re-reads definitions from files and
/// storage, rebuilds its route table, and keeps the old table if the new
/// config fails to load (logged per pod).
#[utoipa::path(post, path = "/g2/reload", tag = "system",
    security(("admin_secret" = [])),
    responses(
        (status = 200, description = "Nudge broadcast; pods reload asynchronously"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Storage backend unavailable"),
    ))]
async fn reload(State(state): State<AdminState>) -> Response {
    let channel = g2_core::config::reload_channel(g2_core::DEFAULT_ORG_ID);
    match state.storage.publish(&channel, "reload").await {
        Ok(()) => {
            tracing::info!("reload nudge broadcast");
            Json(serde_json::json!({ "status": "ok", "message": "reload broadcast" }))
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "reload broadcast failed");
            error_response(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
        }
    }
}

/// Authenticated fallback for unmatched admin paths.
async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "no such admin endpoint")
}

/// A JSON `{"error": …}` response with `status`.
fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use g2_storage::MemoryStorage;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;

    const SECRET: &str = "test-admin-secret";

    fn test_router(storage: MemoryStorage) -> Router {
        router(SECRET, Arc::new(storage), None, None).expect("router")
    }

    fn request(path: &str, secret: Option<&str>) -> Request {
        let mut builder = Request::builder().uri(path);
        if let Some(secret) = secret {
            builder = builder.header(ADMIN_AUTH_HEADER, secret);
        }
        builder.body(Body::empty()).expect("request")
    }

    /// An authenticated request with a JSON body.
    fn json_request(method: &str, path: &str, body: &serde_json::Value) -> Request {
        Request::builder()
            .method(method)
            .uri(path)
            .header(ADMIN_AUTH_HEADER, SECRET)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request")
    }

    async fn send(router: Router, req: Request) -> (StatusCode, String) {
        let resp = router.oneshot(req).await.expect("infallible");
        let status = resp.status();
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        (status, String::from_utf8(body.to_vec()).expect("utf8"))
    }

    async fn call(path: &str, secret: Option<&str>) -> (StatusCode, String) {
        send(test_router(MemoryStorage::new()), request(path, secret)).await
    }

    #[test]
    fn empty_secret_is_rejected_at_construction() {
        for empty in ["", "   "] {
            assert!(
                router(empty, Arc::new(MemoryStorage::new()), None, None).is_err(),
                "secret `{empty:?}` must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn health_needs_no_secret() {
        let (status, body) = call("/g2/health", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"status\":\"pass\""), "body: {body}");
    }

    #[tokio::test]
    async fn metrics_endpoint_is_503_without_wiring() {
        let (status, body) = call("/metrics", None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("metrics not enabled"), "body: {body}");
    }

    #[tokio::test]
    async fn metrics_endpoint_needs_no_secret_and_renders_prometheus_text() {
        let (_provider, handle) = g2_telemetry::metrics::build_meter_provider(None, true)
            .expect("meter provider")
            .expect("prometheus enabled");
        let router = router(
            SECRET,
            Arc::new(MemoryStorage::new()),
            None,
            Some(handle.expect("prometheus handle")),
        )
        .expect("router");

        let resp = router
            .oneshot(request("/metrics", None))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(content_type.starts_with("text/plain"), "{content_type}");
        // Rendering an empty registry is a valid (empty) exposition; the
        // instrument-level rendering is unit-tested in g2-telemetry.
    }

    #[tokio::test]
    async fn missing_and_wrong_secret_are_403() {
        for (name, secret) in [("missing", None), ("wrong", Some("nope"))] {
            let (status, body) = call("/g2/version", secret).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "case: {name}");
            assert!(body.contains(FORBIDDEN_MSG), "case {name}: body: {body}");
        }
    }

    #[tokio::test]
    async fn correct_secret_returns_version() {
        let (status, body) = call("/g2/version", Some(SECRET)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains(env!("CARGO_PKG_VERSION")),
            "body should carry the version: {body}"
        );
    }

    #[tokio::test]
    async fn unknown_paths_are_403_without_secret_and_404_with_it() {
        let (status, _) = call("/g2/nope", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, body) = call("/g2/nope", Some(SECRET)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("no such admin endpoint"), "body: {body}");
    }

    mod dashboard {
        use g2_core::ApiDefinition;
        use g2_middleware::StatsRegistry;
        use g2_proxy::{Forwarder, Gateway, RouteTable};

        use super::*;

        fn dashboard_router(storage: MemoryStorage) -> (Router, Arc<Gateway>, Arc<StatsRegistry>) {
            let shared: g2_storage::SharedStorage = Arc::new(storage);
            let def: ApiDefinition = serde_json::from_str(
                r#"{"api_id":"echo","name":"Echo","listen_path":"/echo/",
                    "target_url":"http://up.internal","auth":{"mode":"keyless"}}"#,
            )
            .expect("def");
            let stats = Arc::new(StatsRegistry::new());
            let forwarder = Forwarder::new();
            let table = RouteTable::build(
                vec![def],
                &g2_proxy::RouteResources {
                    stats: Some(&stats),
                    ..g2_proxy::RouteResources::new(&forwarder, &shared)
                },
            )
            .expect("table");
            let gateway = Arc::new(Gateway::new(table));
            let router = router(
                SECRET,
                shared,
                Some(Dashboard::new(Arc::clone(&gateway), Arc::clone(&stats))),
                None,
            )
            .expect("router");
            (router, gateway, stats)
        }

        #[tokio::test]
        async fn node_reports_version_and_loaded_apis() {
            let (router, _gateway, _stats) = dashboard_router(MemoryStorage::new());
            let (status, body) = send(router, request("/g2/node", Some(SECRET))).await;
            assert_eq!(status, StatusCode::OK);
            let node: serde_json::Value = serde_json::from_str(&body).expect("json");
            assert_eq!(node["version"], env!("CARGO_PKG_VERSION"));
            assert_eq!(node["routes"], 1);
            assert_eq!(node["apis"][0]["api_id"], "echo");
            assert_eq!(node["apis"][0]["auth_mode"], "keyless");
        }

        #[tokio::test]
        async fn stats_snapshot_lists_built_apis() {
            let (router, _gateway, stats) = dashboard_router(MemoryStorage::new());
            // The route build registered the API; traffic-driven counting
            // is unit-tested in g2-middleware::stats.
            let _ = stats.for_api("echo"); // idempotent handle, same counters
            let (status, body) = send(router, request("/g2/stats", Some(SECRET))).await;
            assert_eq!(status, StatusCode::OK);
            let snap: serde_json::Value = serde_json::from_str(&body).expect("json");
            assert_eq!(snap["apis"][0]["api_id"], "echo");
            assert_eq!(snap["apis"][0]["requests"], 0);
        }

        #[tokio::test]
        async fn dashboard_endpoints_are_503_without_wiring() {
            for path in ["/g2/node", "/g2/stats"] {
                let (status, body) = send(
                    test_router(MemoryStorage::new()),
                    request(path, Some(SECRET)),
                )
                .await;
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "path: {path}");
                assert!(body.contains("unavailable"), "body: {body}");
            }
        }
    }

    mod resources {
        use g2_core::api_definition::api_definition_storage_key;
        use g2_core::policy::policy_storage_key;
        use g2_storage::Storage as _;

        use super::*;

        fn api_json(api_id: &str, listen_path: &str) -> serde_json::Value {
            serde_json::json!({
                "api_id": api_id,
                "name": api_id,
                "listen_path": listen_path,
                "target_url": "http://up.internal",
            })
        }

        fn policy_json(policy_id: &str) -> serde_json::Value {
            serde_json::json!({
                "policy_id": policy_id,
                "name": policy_id,
                "rate": { "requests": 10, "per_seconds": 60 },
            })
        }

        fn method_request(method: &str, path: &str) -> Request {
            Request::builder()
                .method(method)
                .uri(path)
                .header(ADMIN_AUTH_HEADER, SECRET)
                .body(Body::empty())
                .expect("request")
        }

        #[tokio::test]
        async fn api_create_fetch_list_delete_round_trips() {
            let storage = MemoryStorage::new();

            let (status, body) = send(
                test_router(storage.clone()),
                json_request("POST", "/g2/apis", &api_json("users", "/users/")),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "body: {body}");
            assert!(body.contains("\"action\":\"added\""), "body: {body}");

            // Stored exactly where the definition loader reads it.
            let stored = storage
                .get(&api_definition_storage_key(
                    g2_core::DEFAULT_ORG_ID,
                    "users",
                ))
                .await
                .expect("get");
            assert!(stored.is_some());

            let (status, body) = send(
                test_router(storage.clone()),
                request("/g2/apis/users", Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let def: g2_core::ApiDefinition = serde_json::from_str(&body).expect("definition");
            assert_eq!(def.listen_path, "/users/");

            // List returns the full records sorted by id.
            send(
                test_router(storage.clone()),
                json_request("POST", "/g2/apis", &api_json("admin", "/admin/")),
            )
            .await;
            let (status, body) = send(
                test_router(storage.clone()),
                request("/g2/apis", Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let listed: Vec<g2_core::ApiDefinition> = serde_json::from_str(&body).expect("list");
            let ids: Vec<_> = listed.iter().map(|d| d.api_id.as_str()).collect();
            assert_eq!(ids, ["admin", "users"]);

            let (status, body) = send(
                test_router(storage.clone()),
                method_request("DELETE", "/g2/apis/users"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("\"action\":\"deleted\""), "body: {body}");
            let (status, _) = send(
                test_router(storage),
                request("/g2/apis/users", Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn post_of_existing_id_is_409_put_updates() {
            let storage = MemoryStorage::new();
            send(
                test_router(storage.clone()),
                json_request("POST", "/g2/apis", &api_json("users", "/users/")),
            )
            .await;

            let (status, body) = send(
                test_router(storage.clone()),
                json_request("POST", "/g2/apis", &api_json("users", "/other/")),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "body: {body}");

            let (status, body) = send(
                test_router(storage.clone()),
                json_request("PUT", "/g2/apis/users", &api_json("users", "/other/")),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("\"action\":\"modified\""), "body: {body}");

            // PUT of a fresh id reports "added".
            let (status, body) = send(
                test_router(storage),
                json_request("PUT", "/g2/apis/new", &api_json("new", "/new/")),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("\"action\":\"added\""), "body: {body}");
        }

        #[tokio::test]
        async fn put_with_mismatched_body_id_is_400() {
            let (status, body) = send(
                test_router(MemoryStorage::new()),
                json_request("PUT", "/g2/apis/users", &api_json("other", "/users/")),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body.contains("does not match path id"), "body: {body}");
        }

        #[tokio::test]
        async fn invalid_bodies_are_400_with_reason() {
            let (status, body) = send(
                test_router(MemoryStorage::new()),
                json_request("POST", "/g2/apis", &api_json("bad", "no-leading-slash")),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body.contains("listen_path"), "body: {body}");

            let mut policy = policy_json("bad");
            policy["rate"]["requests"] = serde_json::json!(0);
            let (status, body) = send(
                test_router(MemoryStorage::new()),
                json_request("POST", "/g2/policies", &policy),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body.contains("rate.requests"), "body: {body}");
        }

        #[tokio::test]
        async fn policy_crud_round_trips_where_auth_reads_it() {
            let storage = MemoryStorage::new();
            let (status, body) = send(
                test_router(storage.clone()),
                json_request("POST", "/g2/policies", &policy_json("free-tier")),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "body: {body}");

            // Stored exactly where the auth middleware resolves policies.
            let stored = storage
                .get(&policy_storage_key(g2_core::DEFAULT_ORG_ID, "free-tier"))
                .await
                .expect("get");
            assert!(stored.is_some());

            let (status, body) = send(
                test_router(storage.clone()),
                request("/g2/policies/free-tier", Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let policy: g2_core::Policy = serde_json::from_str(&body).expect("policy");
            assert_eq!(policy.rate.expect("rate").requests, 10);

            let (status, _) = send(
                test_router(storage.clone()),
                method_request("DELETE", "/g2/policies/free-tier"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (status, _) = send(
                test_router(storage),
                request("/g2/policies/free-tier", Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn empty_collections_list_as_empty_arrays() {
            for path in ["/g2/apis", "/g2/policies"] {
                let (status, body) = send(
                    test_router(MemoryStorage::new()),
                    request(path, Some(SECRET)),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "path: {path}");
                assert_eq!(body, "[]", "path: {path}");
            }
        }

        #[tokio::test]
        async fn resource_routes_require_the_admin_secret() {
            for path in ["/g2/apis", "/g2/policies", "/g2/apis/x", "/g2/policies/x"] {
                let (status, _) =
                    send(test_router(MemoryStorage::new()), request(path, None)).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "path: {path}");
            }
        }
    }

    mod keys {
        use g2_core::session::{hash_key, session_storage_key};
        use g2_core::KeySession;
        use g2_storage::Storage as _;

        use super::*;

        fn session_json() -> serde_json::Value {
            serde_json::json!({ "alias": "test-key", "access": { "users": {} } })
        }

        #[tokio::test]
        async fn create_then_fetch_round_trips() {
            let storage = MemoryStorage::new();

            let (status, body) = send(
                test_router(storage.clone()),
                json_request("POST", "/g2/keys", &session_json()),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "body: {body}");
            let created: serde_json::Value = serde_json::from_str(&body).expect("json");
            let raw_key = created["key"].as_str().expect("raw key");
            assert_eq!(
                created["key_hash"].as_str(),
                Some(hash_key(raw_key).as_str())
            );
            assert_eq!(created["action"], "added");

            // Fetch by raw key…
            let (status, body) = send(
                test_router(storage.clone()),
                request(&format!("/g2/keys/{raw_key}"), Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let session: KeySession = serde_json::from_str(&body).expect("session");
            assert_eq!(session.alias.as_deref(), Some("test-key"));

            // …and by hash.
            let (status, _) = send(
                test_router(storage),
                request(
                    &format!("/g2/keys/{}?hashed=true", hash_key(raw_key)),
                    Some(SECRET),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        #[tokio::test]
        async fn put_reports_added_then_modified() {
            let storage = MemoryStorage::new();

            let (status, body) = send(
                test_router(storage.clone()),
                json_request("PUT", "/g2/keys/my-raw-key", &session_json()),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {body}");
            assert!(body.contains("\"action\":\"added\""), "body: {body}");

            let (status, body) = send(
                test_router(storage.clone()),
                json_request("PUT", "/g2/keys/my-raw-key", &session_json()),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("\"action\":\"modified\""), "body: {body}");

            // The session landed under the hashed storage key.
            let stored = storage
                .get(&session_storage_key(
                    g2_core::DEFAULT_ORG_ID,
                    &hash_key("my-raw-key"),
                ))
                .await
                .expect("get");
            assert!(stored.is_some());
        }

        #[tokio::test]
        async fn put_provisions_basic_auth_users() {
            let storage = MemoryStorage::new();
            let body = serde_json::json!({
                "alias": "alice",
                "basic_auth": { "password_hash": "$2b$04$placeholderplaceholder" }
            });
            let (status, _) = send(
                test_router(storage.clone()),
                json_request("PUT", "/g2/keys/basic:alice", &body),
            )
            .await;
            assert_eq!(status, StatusCode::OK);

            // Stored exactly where basic-auth middleware looks it up.
            let stored = storage
                .get(&session_storage_key(
                    g2_core::DEFAULT_ORG_ID,
                    &hash_key("basic:alice"),
                ))
                .await
                .expect("get");
            assert!(stored.is_some());
        }

        #[tokio::test]
        async fn invalid_session_body_is_400() {
            let body = serde_json::json!({ "rate": { "requests": 0, "per_seconds": 60 } });
            let (status, resp) = send(
                test_router(MemoryStorage::new()),
                json_request("POST", "/g2/keys", &body),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(resp.contains("rate.requests"), "body: {resp}");
        }

        #[tokio::test]
        async fn unknown_key_is_404_on_get_and_delete() {
            let (status, _) = send(
                test_router(MemoryStorage::new()),
                request("/g2/keys/nope", Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            let (status, _) = send(
                test_router(MemoryStorage::new()),
                Request::builder()
                    .method("DELETE")
                    .uri("/g2/keys/nope")
                    .header(ADMIN_AUTH_HEADER, SECRET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn delete_removes_the_key() {
            let storage = MemoryStorage::new();
            send(
                test_router(storage.clone()),
                json_request("PUT", "/g2/keys/doomed", &session_json()),
            )
            .await;

            let (status, body) = send(
                test_router(storage.clone()),
                Request::builder()
                    .method("DELETE")
                    .uri("/g2/keys/doomed")
                    .header(ADMIN_AUTH_HEADER, SECRET)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("\"action\":\"deleted\""), "body: {body}");

            let (status, _) = send(
                test_router(storage),
                request("/g2/keys/doomed", Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn list_returns_sorted_hashes_for_the_org() {
            let storage = MemoryStorage::new();
            for raw in ["key-one", "key-two"] {
                send(
                    test_router(storage.clone()),
                    json_request("PUT", &format!("/g2/keys/{raw}"), &session_json()),
                )
                .await;
            }
            // A key in another org must not be listed.
            storage
                .set("g2:other-org:apikey:deadbeef", "{}", None)
                .await
                .expect("seed");

            let (status, body) = send(
                test_router(storage.clone()),
                request("/g2/keys", Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let listed: serde_json::Value = serde_json::from_str(&body).expect("json");
            let mut expected = vec![hash_key("key-one"), hash_key("key-two")];
            expected.sort_unstable();
            assert_eq!(listed["keys"], serde_json::json!(expected), "body: {body}");

            let (status, body) = send(
                test_router(storage),
                request("/g2/keys?org_id=empty-org", Some(SECRET)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("\"keys\":[]"), "body: {body}");
        }

        #[tokio::test]
        async fn keys_require_the_admin_secret() {
            let (status, _) = send(
                test_router(MemoryStorage::new()),
                request("/g2/keys/anything", None),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }
}
