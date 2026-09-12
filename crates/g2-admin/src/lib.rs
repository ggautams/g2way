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
//! Today the surface is a skeleton: `/g2/health` (liveness, unauthenticated)
//! and `/g2/version` (authenticated). Key CRUD (`/g2/keys`) lands next;
//! definition/policy CRUD and `/g2/reload` arrive in milestone M4.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use g2_core::Error;
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
}

impl AdminState {
    fn secret_matches(&self, presented: &str) -> bool {
        let presented: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        presented == self.secret_digest
    }
}

/// Builds the admin API router, gated by `admin_secret`.
///
/// # Errors
///
/// Returns [`Error::InvalidGatewayConfig`] when `admin_secret` is empty:
/// the admin API never runs unsecured. (The binary also enforces this via
/// [`g2_core::GatewayConfig::validate`]; this is defense in depth for other
/// callers.)
pub fn router(admin_secret: &str) -> Result<Router, Error> {
    if admin_secret.trim().is_empty() {
        return Err(Error::InvalidGatewayConfig {
            reason: "admin secret must not be empty".into(),
        });
    }
    let state = AdminState {
        secret_digest: Sha256::digest(admin_secret.as_bytes()).into(),
    };

    // The fallback lives inside the authed router so unknown paths are
    // only distinguishable from known ones by authenticated callers.
    let authed = Router::new()
        .route("/g2/version", get(version))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state, require_admin_secret));

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
    use axum::body::Body;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;

    const SECRET: &str = "test-admin-secret";

    fn request(path: &str, secret: Option<&str>) -> Request {
        let mut builder = Request::builder().uri(path);
        if let Some(secret) = secret {
            builder = builder.header(ADMIN_AUTH_HEADER, secret);
        }
        builder.body(Body::empty()).expect("request")
    }

    async fn call(path: &str, secret: Option<&str>) -> (StatusCode, String) {
        let resp = router(SECRET)
            .expect("router")
            .oneshot(request(path, secret))
            .await
            .expect("infallible");
        let status = resp.status();
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        (status, String::from_utf8(body.to_vec()).expect("utf8"))
    }

    #[test]
    fn empty_secret_is_rejected_at_construction() {
        for empty in ["", "   "] {
            assert!(
                router(empty).is_err(),
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
        let (status, _) = call("/g2/keys", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, body) = call("/g2/keys", Some(SECRET)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("no such admin endpoint"), "body: {body}");
    }
}
