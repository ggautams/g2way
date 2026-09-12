//! Locally generated JSON responses: errors and health checks.

use bytes::Bytes;
use g2_middleware::ProxyBody;
use http::{header, HeaderValue, Response, StatusCode};
use http_body_util::Full;

/// Gateway version reported by `/hello` (the workspace version).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Builds a JSON error response: `{"error": "<message>"}`.
pub(crate) fn error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body = serde_json::json!({ "error": message }).to_string();
    json_response(status, body)
}

/// Builds the `/hello` / `/ready` liveness body.
pub(crate) fn health_response() -> Response<ProxyBody> {
    let body = serde_json::json!({
        "status": "pass",
        "version": VERSION,
        "description": "g2way API gateway",
    })
    .to_string();
    json_response(StatusCode::OK, body)
}

fn json_response(status: StatusCode, body: String) -> Response<ProxyBody> {
    let mut resp = Response::new(ProxyBody::new(Full::new(Bytes::from(body))));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}
