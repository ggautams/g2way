//! Token authentication: resolve a client credential to a [`KeySession`].
//!
//! [`AuthLayer`] implements the `auth_token` mode of
//! [`AuthConfig`]: the token is extracted from the
//! configured carrier (header, then query parameter, then cookie), hashed
//! with SHA-256, and looked up in [`Storage`](g2_storage::Storage) under
//! `g2:{org_id}:apikey:{hash}`. A live session is stamped onto the request
//! as a [`SessionContext`] extension for downstream layers; anything else is
//! rejected before the request reaches the upstream.
//!
//! Keyless APIs simply do not get this layer (see
//! [`ChainBuilder`](crate::ChainBuilder)).
//!
//! # Responses
//!
//! - `401` — no token found in any configured carrier.
//! - `403` — token unknown, session inactive/expired, or the session does
//!   not grant this API. One message for all three: which one it was must
//!   not leak to the caller.
//! - `503` — the storage backend errored; the request may be retried.
//! - `500` — the stored session record is not valid JSON (an operational
//!   bug, logged loudly).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use g2_core::session::{hash_key, session_storage_key};
use g2_core::{AuthConfig, Error, KeySession};
use g2_storage::SharedStorage;
use http::header::HeaderName;
use http::{header, Request, Response, StatusCode};
use tower::{Layer, Service};

use crate::context::SessionContext;
use crate::response::json_error;
use crate::ProxyBody;

/// Message for every "you may not pass" rejection; deliberately does not
/// distinguish unknown key / inactive / expired / wrong API.
const FORBIDDEN_MSG: &str = "access to this API has been disallowed";

/// Where the auth token is read from, precomputed at route-build time.
struct AuthState {
    /// Header carrying the token (an optional `Bearer ` prefix is stripped).
    header: HeaderName,
    /// Optional query parameter also accepted as a carrier.
    query_param: Option<String>,
    /// Optional cookie name also accepted as a carrier.
    cookie: Option<String>,
    storage: SharedStorage,
    api_id: Arc<str>,
    org_id: Arc<str>,
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthState")
            .field("header", &self.header)
            .field("query_param", &self.query_param)
            .field("cookie", &self.cookie)
            .field("api_id", &self.api_id)
            .field("org_id", &self.org_id)
            .finish_non_exhaustive() // storage is a trait object
    }
}

/// Tower layer adding token authentication to an API's chain.
#[derive(Debug, Clone)]
pub struct AuthLayer {
    state: Arc<AuthState>,
}

impl AuthLayer {
    /// Builds the layer for `cfg`, or `None` when the API is keyless.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] if the configured header name
    /// is invalid (normally caught earlier by definition validation).
    pub fn from_config(
        cfg: &AuthConfig,
        storage: SharedStorage,
        api_id: &str,
        org_id: &str,
    ) -> Result<Option<Self>, Error> {
        match cfg {
            AuthConfig::Keyless => Ok(None),
            AuthConfig::AuthToken {
                header,
                query_param,
                cookie,
            } => {
                let header = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                    Error::InvalidApiDefinition {
                        api: api_id.to_owned(),
                        reason: format!("`auth.header` is not a valid header name: `{header}`"),
                    }
                })?;
                Ok(Some(Self {
                    state: Arc::new(AuthState {
                        header,
                        query_param: query_param.clone(),
                        cookie: cookie.clone(),
                        storage,
                        api_id: api_id.into(),
                        org_id: org_id.into(),
                    }),
                }))
            }
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = Auth<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Auth {
            inner,
            state: Arc::clone(&self.state),
        }
    }
}

/// The [`Service`] produced by [`AuthLayer`].
#[derive(Debug, Clone)]
pub struct Auth<S> {
    inner: S,
    state: Arc<AuthState>,
}

impl<S> Service<Request<ProxyBody>> for Auth<S>
where
    S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ProxyBody>) -> Self::Future {
        let state = Arc::clone(&self.state);
        // Standard tower pattern: move the polled-ready service into the
        // future, leave a fresh clone behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let Some(token) = extract_token(&state, &req) else {
                return Ok(json_error(
                    StatusCode::UNAUTHORIZED,
                    "authorization field missing",
                ));
            };

            let key_hash = hash_key(&token);
            let storage_key = session_storage_key(&state.org_id, &key_hash);
            let record = match state.storage.get(&storage_key).await {
                Ok(record) => record,
                Err(e) => {
                    tracing::error!(api_id = %state.api_id, error = %e, "auth storage lookup failed");
                    return Ok(json_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "key storage unavailable",
                    ));
                }
            };
            let Some(record) = record else {
                return Ok(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
            };
            let session: KeySession = match serde_json::from_str(&record) {
                Ok(session) => session,
                Err(e) => {
                    tracing::error!(
                        api_id = %state.api_id,
                        key_hash = %key_hash,
                        error = %e,
                        "stored key session is not valid JSON"
                    );
                    return Ok(json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "malformed key session record",
                    ));
                }
            };

            if !session.active
                || session.is_expired(unix_now_secs())
                || !session.allows_api(&state.api_id)
            {
                return Ok(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
            }

            req.extensions_mut()
                .insert(SessionContext::new(session, key_hash));
            inner.call(req).await
        })
    }
}

/// Seconds since the Unix epoch (0 if the clock is set before 1970).
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pulls the token out of the first configured carrier that has one:
/// header, then query parameter, then cookie.
///
/// Query and cookie values are matched verbatim (no percent-decoding):
/// tokens are opaque strings the gateway itself hands out, and they never
/// contain characters that need escaping.
fn extract_token(state: &AuthState, req: &Request<ProxyBody>) -> Option<String> {
    if let Some(value) = req.headers().get(&state.header) {
        if let Ok(value) = value.to_str() {
            let token = strip_bearer(value.trim());
            if !token.is_empty() {
                return Some(token.to_owned());
            }
        }
    }

    if let Some(param) = &state.query_param {
        if let Some(query) = req.uri().query() {
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k == param && !v.is_empty() {
                        return Some(v.to_owned());
                    }
                }
            }
        }
    }

    if let Some(name) = &state.cookie {
        for value in req.headers().get_all(header::COOKIE) {
            let Ok(value) = value.to_str() else { continue };
            for part in value.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    if k == name && !v.is_empty() {
                        return Some(v.to_owned());
                    }
                }
            }
        }
    }

    None
}

/// Strips a leading case-insensitive `Bearer ` scheme from a header value.
fn strip_bearer(value: &str) -> &str {
    match value.split_at_checked(7) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer ") => rest.trim_start(),
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use g2_storage::{MemoryStorage, Storage};
    use http_body_util::Full;
    use tower::ServiceExt;

    use super::*;

    const API: &str = "users-api";
    const ORG: &str = "default";

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    /// Inner service asserting a `SessionContext` was attached; echoes the
    /// session alias in a response header.
    async fn require_session(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let ctx = req
            .extensions()
            .get::<SessionContext>()
            .expect("SessionContext must be set for authed requests");
        let mut resp = Response::new(body());
        let alias = ctx.session().alias.clone().unwrap_or_default();
        resp.headers_mut().insert(
            "x-echo-alias",
            http::HeaderValue::from_str(&alias).expect("alias"),
        );
        Ok(resp)
    }

    fn token_cfg(query_param: Option<&str>, cookie: Option<&str>) -> AuthConfig {
        AuthConfig::AuthToken {
            header: "Authorization".into(),
            query_param: query_param.map(str::to_owned),
            cookie: cookie.map(str::to_owned),
        }
    }

    async fn seed(storage: &MemoryStorage, raw_key: &str, session: &KeySession) {
        let key = session_storage_key(ORG, &hash_key(raw_key));
        storage
            .set(&key, &serde_json::to_string(session).expect("json"), None)
            .await
            .expect("seed");
    }

    fn service(cfg: &AuthConfig, storage: MemoryStorage) -> crate::ChainService {
        let layer = AuthLayer::from_config(cfg, Arc::new(storage), API, ORG)
            .expect("valid cfg")
            .expect("token mode");
        crate::ChainService::new(layer.layer(tower::service_fn(require_session)))
    }

    fn request(uri: &str) -> Request<ProxyBody> {
        Request::builder().uri(uri).body(body()).expect("request")
    }

    #[test]
    fn keyless_config_builds_no_layer() {
        let layer = AuthLayer::from_config(
            &AuthConfig::Keyless,
            Arc::new(MemoryStorage::new()),
            API,
            ORG,
        )
        .expect("ok");
        assert!(layer.is_none());
    }

    #[tokio::test]
    async fn missing_token_is_401() {
        let svc = service(&token_cfg(None, None), MemoryStorage::new());
        let resp = svc.oneshot(request("/x")).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_token_is_403() {
        let svc = service(&token_cfg(None, None), MemoryStorage::new());
        let mut req = request("/x");
        req.headers_mut()
            .insert("authorization", "nope".parse().expect("value"));
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn valid_header_token_passes_with_session_context() {
        let storage = MemoryStorage::new();
        let session = KeySession {
            alias: Some("mobile".into()),
            ..KeySession::default()
        };
        seed(&storage, "secret-key", &session).await;

        let svc = service(&token_cfg(None, None), storage);
        // `Bearer ` prefix must be stripped, case-insensitively.
        let mut req = request("/x");
        req.headers_mut()
            .insert("authorization", "bEaReR secret-key".parse().expect("value"));
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-echo-alias")
                .expect("alias")
                .as_bytes(),
            b"mobile"
        );
    }

    #[tokio::test]
    async fn query_param_and_cookie_carriers_work() {
        let storage = MemoryStorage::new();
        seed(&storage, "qk", &KeySession::default()).await;
        seed(&storage, "ck", &KeySession::default()).await;

        let cfg = token_cfg(Some("api_key"), Some("g2token"));

        let resp = service(&cfg, storage.clone())
            .oneshot(request("/x?other=1&api_key=qk"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);

        let mut req = request("/x");
        req.headers_mut().insert(
            header::COOKIE,
            "a=b; g2token=ck".parse().expect("cookie value"),
        );
        let resp = service(&cfg, storage)
            .oneshot(req)
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn inactive_expired_and_unauthorized_api_are_403() {
        let storage = MemoryStorage::new();
        seed(
            &storage,
            "inactive",
            &KeySession {
                active: false,
                ..KeySession::default()
            },
        )
        .await;
        seed(
            &storage,
            "expired",
            &KeySession {
                expires_at: Some(1), // 1970: long past
                ..KeySession::default()
            },
        )
        .await;
        seed(
            &storage,
            "other-api",
            &KeySession {
                access: [("not-this-api".to_owned(), Default::default())].into(),
                ..KeySession::default()
            },
        )
        .await;

        for token in ["inactive", "expired", "other-api"] {
            let mut req = request("/x");
            req.headers_mut()
                .insert("authorization", token.parse().expect("value"));
            let resp = service(&token_cfg(None, None), storage.clone())
                .oneshot(req)
                .await
                .expect("infallible");
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "token `{token}`");
        }
    }

    #[tokio::test]
    async fn malformed_session_record_is_500() {
        let storage = MemoryStorage::new();
        let key = session_storage_key(ORG, &hash_key("bad"));
        storage.set(&key, "not json", None).await.expect("seed");

        let mut req = request("/x");
        req.headers_mut()
            .insert("authorization", "bad".parse().expect("value"));
        let resp = service(&token_cfg(None, None), storage)
            .oneshot(req)
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn bearer_stripping_rules() {
        assert_eq!(strip_bearer("Bearer abc"), "abc");
        assert_eq!(strip_bearer("BEARER  abc"), "abc");
        assert_eq!(strip_bearer("bearer"), "bearer"); // no space: not a scheme
        assert_eq!(strip_bearer("abc"), "abc");
        assert_eq!(strip_bearer("Bearerabc"), "Bearerabc");
    }
}
