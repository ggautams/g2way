//! JSON error responses produced by middleware layers.

use bytes::Bytes;
use http::{header, HeaderValue, Response, StatusCode};
use http_body_util::Full;

use crate::ProxyBody;

/// Builds a JSON error response: `{"error": "<message>"}`.
///
/// The shape matches the gateway's routing errors (404/502/504) so clients
/// see one error format regardless of which layer rejected the request.
#[must_use]
pub fn json_error(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body = serde_json::json!({ "error": message }).to_string();
    let mut resp = Response::new(ProxyBody::new(Full::new(Bytes::from(body))));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn error_response_is_json_with_status() {
        let resp = json_error(StatusCode::UNAUTHORIZED, "authorization field missing");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).expect("ct"),
            "application/json"
        );
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(body.as_ref(), br#"{"error":"authorization field missing"}"#);
    }
}
