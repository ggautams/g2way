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
//! Endpoints: `/g2/health` (liveness, unauthenticated), `/g2/version`
//! (authenticated) and key CRUD under `/g2/keys` (authenticated; raw keys
//! are returned only at creation — storage holds hashes, see
//! [`g2_core::session::hash_key`]). Definition/policy CRUD and `/g2/reload`
//! arrive in milestone M4.

mod keys;

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
pub fn router(admin_secret: &str, storage: SharedStorage) -> Result<Router, Error> {
    if admin_secret.trim().is_empty() {
        return Err(Error::InvalidGatewayConfig {
            reason: "admin secret must not be empty".into(),
        });
    }
    let state = AdminState {
        secret_digest: Sha256::digest(admin_secret.as_bytes()).into(),
        storage,
    };

    // The fallback lives inside the authed router so unknown paths are
    // only distinguishable from known ones by authenticated callers.
    let authed = Router::new()
        .route("/g2/version", get(version))
        .route("/g2/keys", post(keys::create_key))
        .route(
            "/g2/keys/{key}",
            get(keys::get_key)
                .put(keys::put_key)
                .delete(keys::delete_key),
        )
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_secret,
        ))
        .with_state(state);

    Ok(Router::new().route("/g2/health", get(health)).merge(authed))
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
async fn health() -> Response {
    Json(serde_json::json!({ "status": "pass" })).into_response()
}

/// `GET /g2/version` — the gateway's version (workspace-wide, so the crate
/// version equals the binary's).
async fn version() -> Response {
    Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") })).into_response()
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
        router(SECRET, Arc::new(storage)).expect("router")
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
                router(empty, Arc::new(MemoryStorage::new())).is_err(),
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
