//! Credential authentication: resolve a client credential to a
//! [`KeySession`].
//!
//! [`AuthLayer`] implements the credentialed modes of [`AuthConfig`]:
//!
//! - **`auth_token`** — the token is extracted from the configured carrier
//!   (header, then query parameter, then cookie), hashed with SHA-256, and
//!   looked up in [`Storage`](g2_storage::Storage) under
//!   `g2:{org_id}:apikey:{hash}`.
//! - **`jwt`** — the bearer token in the configured header is verified
//!   against a static key (HS256 secret or RS256 public key) and its claims
//!   are turned into an ephemeral session: no storage lookup, `expires_at`
//!   from `exp`, alias from the identity claim, access restricted to this
//!   API.
//! - **`basic_auth`** — RFC 7617 `Authorization: Basic base64(user:pass)`.
//!   The username (hashed under a `basic:` namespace) resolves to a stored
//!   session whose `basic_auth.password_hash` the presented password is
//!   bcrypt-verified against. Verification runs on the blocking pool
//!   (bcrypt costs ~100ms by design); per-user verification caching is a
//!   possible later optimization, deliberately not built yet.
//!
//! Either way a live session is stamped onto the request as a
//! [`SessionContext`] extension for downstream layers; anything else is
//! rejected before the request reaches the upstream.
//!
//! Keyless APIs simply do not get this layer (see
//! [`ChainBuilder`](crate::ChainBuilder)).
//!
//! # Responses
//!
//! - `401` — no token found in any configured carrier. For basic auth this
//!   covers every "no parseable credential" case (missing header, wrong
//!   scheme, bad base64/UTF-8, no `:`, empty username) and carries a
//!   `WWW-Authenticate: Basic realm="…"` challenge.
//! - `403` — token unknown or fails verification, wrong password, session
//!   inactive/expired, or the session does not grant this API. One message
//!   for all of these: which one it was must not leak to the caller
//!   (details are logged). Unknown basic-auth users still cost one bcrypt
//!   verify (against a dummy hash) so response timing does not reveal
//!   whether a username exists.
//! - `503` — the storage backend errored; the request may be retried.
//! - `500` — the stored session record is not valid JSON or its stored
//!   bcrypt hash is malformed (operational bugs, logged loudly).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use g2_core::session::{hash_key, session_storage_key};
use g2_core::{AuthConfig, Error, JwtSigningMethod, KeySession};
use g2_storage::SharedStorage;
use http::header::{HeaderName, HeaderValue};
use http::{header, Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use tower::{Layer, Service};

use crate::context::SessionContext;
use crate::response::json_error;
use crate::ProxyBody;

/// Message for every "you may not pass" rejection; deliberately does not
/// distinguish unknown key / inactive / expired / wrong API.
const FORBIDDEN_MSG: &str = "access to this API has been disallowed";

/// Message for every basic-auth 401: the request carried no parseable
/// `Basic` credential (missing header, wrong scheme, bad encoding, …).
const BASIC_CHALLENGE_MSG: &str = "invalid basic auth credentials";

/// A well-formed cost-12 bcrypt hash matching no real password. Unknown
/// basic-auth users are "verified" against it so a wrong-username request
/// costs the same as a wrong-password one (no user-enumeration timing
/// oracle). Guarded well-formed by a unit test.
const DUMMY_BCRYPT_HASH: &str = "$2b$12$3neaCJyNondMOTlK7AuGBOMBGI0j/gZ3YsMVx1VJl.1cBJI5DVA32";

/// Everything one API's auth needs, precomputed at route-build time.
struct AuthState {
    api_id: Arc<str>,
    org_id: Arc<str>,
    mode: Mode,
}

/// The credentialed auth modes (keyless builds no layer at all).
enum Mode {
    /// `auth_token`: hash the presented token and look it up in storage.
    Token {
        /// Header carrying the token (an optional `Bearer ` prefix is stripped).
        header: HeaderName,
        /// Optional query parameter also accepted as a carrier.
        query_param: Option<String>,
        /// Optional cookie name also accepted as a carrier.
        cookie: Option<String>,
        storage: SharedStorage,
    },
    /// `jwt`: verify the bearer token against a static key.
    Jwt {
        /// Header carrying the JWT.
        header: HeaderName,
        decoding_key: Box<DecodingKey>,
        validation: Box<Validation>,
        /// Claim used as the caller identity.
        identity_claim: String,
    },
    /// `basic_auth`: resolve the username in storage, bcrypt-verify the
    /// password.
    Basic {
        /// Precomputed `Basic realm="…"` challenge sent on every 401.
        challenge: HeaderValue,
        storage: SharedStorage,
    },
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = match &self.mode {
            Mode::Token { .. } => "token",
            Mode::Jwt { .. } => "jwt",
            Mode::Basic { .. } => "basic",
        };
        f.debug_struct("AuthState")
            .field("api_id", &self.api_id)
            .field("org_id", &self.org_id)
            .field("mode", &mode)
            .finish_non_exhaustive() // key material and storage stay unprintable
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
        let invalid = |reason: String| Error::InvalidApiDefinition {
            api: api_id.to_owned(),
            reason,
        };
        let parse_header = |header: &str| {
            HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                invalid(format!(
                    "`auth.header` is not a valid header name: `{header}`"
                ))
            })
        };

        let mode = match cfg {
            AuthConfig::Keyless => return Ok(None),
            AuthConfig::AuthToken {
                header,
                query_param,
                cookie,
            } => Mode::Token {
                header: parse_header(header)?,
                query_param: query_param.clone(),
                cookie: cookie.clone(),
                storage,
            },
            AuthConfig::Jwt {
                signing_method,
                secret,
                public_key_pem,
                header,
                identity_claim,
            } => {
                let (algorithm, decoding_key) = match signing_method {
                    JwtSigningMethod::Hs256 => {
                        let secret = secret
                            .as_deref()
                            .ok_or_else(|| invalid("hs256 requires `auth.secret`".into()))?;
                        (
                            Algorithm::HS256,
                            DecodingKey::from_secret(secret.as_bytes()),
                        )
                    }
                    JwtSigningMethod::Rs256 => {
                        let pem = public_key_pem.as_deref().ok_or_else(|| {
                            invalid("rs256 requires `auth.public_key_pem`".into())
                        })?;
                        let key = DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
                            invalid(format!("`auth.public_key_pem` is not a valid RSA PEM: {e}"))
                        })?;
                        (Algorithm::RS256, key)
                    }
                };
                // `exp` is required and validated (with the library's default
                // leeway); tokens without an expiry are rejected.
                let validation = Validation::new(algorithm);
                Mode::Jwt {
                    header: parse_header(header)?,
                    decoding_key: Box::new(decoding_key),
                    validation: Box::new(validation),
                    identity_claim: identity_claim.clone(),
                }
            }
            AuthConfig::BasicAuth { realm } => {
                let challenge = HeaderValue::from_str(&format!("Basic realm=\"{realm}\""))
                    .map_err(|_| {
                        invalid(format!(
                            "`auth.realm` cannot be used in a header value: `{realm}`"
                        ))
                    })?;
                Mode::Basic { challenge, storage }
            }
        };
        Ok(Some(Self {
            state: Arc::new(AuthState {
                api_id: api_id.into(),
                org_id: org_id.into(),
                mode,
            }),
        }))
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
            match authenticate(&state, &req).await {
                Ok(session_ctx) => {
                    req.extensions_mut().insert(session_ctx);
                    inner.call(req).await
                }
                Err(resp) => Ok(resp),
            }
        })
    }
}

/// Runs the configured auth mode; `Err` is the ready-to-send rejection.
async fn authenticate(
    state: &AuthState,
    req: &Request<ProxyBody>,
) -> Result<SessionContext, Response<ProxyBody>> {
    match &state.mode {
        Mode::Token {
            header,
            query_param,
            cookie,
            storage,
        } => {
            let token = extract_token(header, query_param.as_deref(), cookie.as_deref(), req)
                .ok_or_else(|| {
                    json_error(StatusCode::UNAUTHORIZED, "authorization field missing")
                })?;
            authenticate_stored_token(state, storage, &token).await
        }
        Mode::Jwt {
            header,
            decoding_key,
            validation,
            identity_claim,
        } => {
            let token = extract_token(header, None, None, req).ok_or_else(|| {
                json_error(StatusCode::UNAUTHORIZED, "authorization field missing")
            })?;
            authenticate_jwt(state, decoding_key, validation, identity_claim, &token)
        }
        Mode::Basic { challenge, storage } => {
            authenticate_basic(state, storage, challenge, req).await
        }
    }
}

/// `basic_auth` mode: resolve the username to a stored [`KeySession`] and
/// bcrypt-verify the password against its `basic_auth.password_hash`.
async fn authenticate_basic(
    state: &AuthState,
    storage: &SharedStorage,
    challenge: &HeaderValue,
    req: &Request<ProxyBody>,
) -> Result<SessionContext, Response<ProxyBody>> {
    let Some((username, password)) = extract_basic_credentials(req) else {
        return Err(basic_challenge_error(challenge));
    };

    // The `basic:` prefix keeps usernames in their own hash namespace, so a
    // username can never collide with the SHA-256 of a stored raw token
    // (same idea as the `jwt:` prefix for JWT identities).
    let key_hash = hash_key(&format!("basic:{username}"));
    let storage_key = session_storage_key(&state.org_id, &key_hash);
    let record = storage.get(&storage_key).await.map_err(|e| {
        tracing::error!(api_id = %state.api_id, error = %e, "auth storage lookup failed");
        json_error(StatusCode::SERVICE_UNAVAILABLE, "key storage unavailable")
    })?;
    let session: Option<KeySession> = match record {
        None => None,
        Some(record) => Some(serde_json::from_str(&record).map_err(|e| {
            tracing::error!(
                api_id = %state.api_id,
                key_hash = %key_hash,
                error = %e,
                "stored key session is not valid JSON"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "malformed key session record",
            )
        })?),
    };

    // Unknown user or a session without basic-auth data still costs one
    // bcrypt verify (against the dummy hash), so timing does not reveal
    // whether the username exists.
    let stored_hash = session
        .as_ref()
        .and_then(|s| s.basic_auth.as_ref())
        .map_or(DUMMY_BCRYPT_HASH, |b| b.password_hash.as_str())
        .to_owned();
    let verify = tokio::task::spawn_blocking(move || bcrypt::verify(password, &stored_hash))
        .await
        .map_err(|e| {
            tracing::error!(api_id = %state.api_id, error = %e, "bcrypt verify task failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "auth verification failed",
            )
        })?;
    let password_matches = verify.map_err(|e| {
        tracing::error!(
            api_id = %state.api_id,
            key_hash = %key_hash,
            error = %e,
            "stored basic-auth password hash is not a valid bcrypt hash"
        );
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth verification failed",
        )
    })?;

    match session {
        Some(session)
            if password_matches
                && session.basic_auth.is_some()
                && session.active
                && !session.is_expired(unix_now_secs())
                && session.allows_api(&state.api_id) =>
        {
            Ok(SessionContext::new(session, key_hash))
        }
        _ => Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG)),
    }
}

/// `auth_token` mode: hash the token and resolve the stored [`KeySession`].
async fn authenticate_stored_token(
    state: &AuthState,
    storage: &SharedStorage,
    token: &str,
) -> Result<SessionContext, Response<ProxyBody>> {
    let key_hash = hash_key(token);
    let storage_key = session_storage_key(&state.org_id, &key_hash);
    let record = storage.get(&storage_key).await.map_err(|e| {
        tracing::error!(api_id = %state.api_id, error = %e, "auth storage lookup failed");
        json_error(StatusCode::SERVICE_UNAVAILABLE, "key storage unavailable")
    })?;
    let Some(record) = record else {
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    };
    let session: KeySession = serde_json::from_str(&record).map_err(|e| {
        tracing::error!(
            api_id = %state.api_id,
            key_hash = %key_hash,
            error = %e,
            "stored key session is not valid JSON"
        );
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "malformed key session record",
        )
    })?;

    if !session.active || session.is_expired(unix_now_secs()) || !session.allows_api(&state.api_id)
    {
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    }
    Ok(SessionContext::new(session, key_hash))
}

/// `jwt` mode: verify the token and synthesize an ephemeral session from
/// its claims. No storage involved.
// The large Err is a rejection Response built once on the cold path; boxing
// it would just move the allocation.
#[allow(clippy::result_large_err)]
fn authenticate_jwt(
    state: &AuthState,
    decoding_key: &DecodingKey,
    validation: &Validation,
    identity_claim: &str,
    token: &str,
) -> Result<SessionContext, Response<ProxyBody>> {
    let claims = jsonwebtoken::decode::<serde_json::Value>(token, decoding_key, validation)
        .map_err(|e| {
            tracing::debug!(api_id = %state.api_id, error = %e, "JWT rejected");
            json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG)
        })?
        .claims;

    let Some(identity) = claims.get(identity_claim).and_then(|v| v.as_str()) else {
        tracing::debug!(
            api_id = %state.api_id,
            identity_claim,
            "JWT valid but identity claim missing or not a string"
        );
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    };
    // `exp` presence and freshness were enforced by `validation`.
    let expires_at = claims.get("exp").and_then(serde_json::Value::as_u64);

    let session = KeySession {
        org_id: state.org_id.to_string(),
        alias: Some(identity.to_owned()),
        expires_at,
        access: std::iter::once((state.api_id.to_string(), Default::default())).collect(),
        ..KeySession::default()
    };
    // The `jwt:` prefix keeps JWT identities from ever colliding with the
    // hash of a real stored token in later rate-limit/quota counters.
    let key_hash = hash_key(&format!("jwt:{identity}"));
    Ok(SessionContext::new(session, key_hash))
}

/// Seconds since the Unix epoch (0 if the clock is set before 1970).
pub(crate) fn unix_now_secs() -> u64 {
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
fn extract_token(
    header: &HeaderName,
    query_param: Option<&str>,
    cookie: Option<&str>,
    req: &Request<ProxyBody>,
) -> Option<String> {
    if let Some(value) = req.headers().get(header) {
        if let Ok(value) = value.to_str() {
            let token = strip_bearer(value.trim());
            if !token.is_empty() {
                return Some(token.to_owned());
            }
        }
    }

    if let Some(param) = query_param {
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

    if let Some(name) = cookie {
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

/// Strips a leading case-insensitive `Basic ` scheme, or `None` when the
/// value does not use the Basic scheme (unlike bearer tokens, a bare value
/// without the scheme is not accepted).
fn strip_basic(value: &str) -> Option<&str> {
    match value.split_at_checked(6) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("basic ") => Some(rest.trim()),
        _ => None,
    }
}

/// Parses RFC 7617 credentials from the `Authorization` header:
/// `Basic base64(username ":" password)`. Returns `None` for anything not
/// parseable (missing header, wrong scheme, bad base64/UTF-8, no `:`, empty
/// username); the password may be empty and may itself contain `:`.
fn extract_basic_credentials(req: &Request<ProxyBody>) -> Option<(String, String)> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = strip_basic(value.trim())?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    if username.is_empty() {
        return None;
    }
    Some((username.to_owned(), password.to_owned()))
}

/// The basic-auth 401: a JSON error carrying the API's `WWW-Authenticate`
/// challenge so plain HTTP clients know how to authenticate.
fn basic_challenge_error(challenge: &HeaderValue) -> Response<ProxyBody> {
    let mut resp = json_error(StatusCode::UNAUTHORIZED, BASIC_CHALLENGE_MSG);
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge.clone());
    resp
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

    mod jwt {
        use jsonwebtoken::{encode, EncodingKey, Header};

        use super::*;

        /// Throwaway RSA keypair generated for these tests only.
        const TEST_RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9vQS0xUUdaCmm
2MuakxbnoUGSCzeKns0F3C3x7I/CSuPV1ckdPIGfOoveNs+mSHI6Z5MwR4SvJcxu
wJZz8dmd9UXHLhr/R2MpOA5cLMdS7ZyVfKrUC0blvWuJ9Un8M2ONmtx97L6c9k07
1HD9MX9NVJlsKKOhF7hvuL+C5Wc8dUsE8TjnHkZ4pCQcHB5eY1BEzHXA0uZqTgsy
4+YfqQ9cT4O+XPVlnPPGuyNe94F/NGqDH0ogfQjc9AEqPVsrOoyejY/oBHmwhSrf
7d8lDzTN6M2KR9L6mZUKUafCKdxw9cfyI/RQRpQq0SK6aeN4/LOiCpvliI+U6Lfd
2MsWr7T/AgMBAAECggEAB5UVKhA0Gd++wl8pi8zS/oCwOSDfoFeGQ/SvlVppyE7r
2fDIL7XqTC2vxzqTg8ajYfgfpq9E+ybci5SArrN8idZyampKQ+dbbBtEX6Sedo7u
Uf8AaKbmt2mhcYru4PhAwzjsFNAwMd+Z6Ikt1sByoOl/lBXvrBFhmn1ckeOPA5hu
j6n2AZyG/nePtFU0y9gi1FTDECM8B2dliQyCzU7LvjpCCbRD0EiKYP7ZpUzIHC65
9WR6RRC3onLe28CueTD3QvAvYsP4QeeiI5wDpvYmLQvowGovRbiAVOHDRqG08gtY
cZSpyVuKmyi6kkRL19wbsTxdyH+elP6Chg1SUowP2QKBgQD/V/SCRSeGV8RrC2AR
rTtujEu73sTOY4kMaDz6LqVk9O3SbqL0ZG1fHP+bah+rA/4LjHbPozbH8d1DXrNc
cVOHoYnVsWp4NWvv7n5OnVUVxr7arbvsX+dDPlcdMQTRyaAV0zL0SmHQN3jqPzb4
BuEqlH6eCzYCngHRi7la3G0X5QKBgQC+OeM7zmL+yPHjG2XS6yBjF6adDrJK/PQE
g+DmfD7lPtEAMnh2cXZ7ADdpcdHu0uha2LRvyCZq1e0SMBFzWd8ny7TQTxn0ZR24
6mIMxO+sWfKLtN4J/37/Qrt6mHo4hXxbIg8SAaiOgxkaLhbbAkobWM51NySaAKru
Fez21p5DEwKBgG1No1cYb0Ds1SHVbrxiYWyDFfBH/gszRHlRLbkSuq4qwpsvzQW8
76ylZy2KEiBMxzT+XeWoQkz41fR+11ydDlqi5bPaDG+Evr2oY90XMFLwDsbhU+5t
Zzu7teLDFwMOwj5VeBxmstREyrfLc6Zcm4p0onbY6bfZF4Ixw5iHfxOZAoGAEwGN
pqgUVAiXwm02W0CK19vBFegmAEAN0XWrvtujHRyNnUttpcfoYpm+75Yjt4zzEkCc
pp6E2B/PtAWBeNj95uf/hOCiYzzHH3arnUL//2RtS3AizzTr520vdixN6d/McP6S
KuZnhPWsSGVaez9bUCgrWKLN0WVHrsoaBv+iiGkCgYEA+y+XusCUErqu/bqzzEYj
Oih8/7hU7lA0CEIx65jqY15F5Q2QDXv/s6j0JKdcWtSkdqq6w/yEbp/AHE8uamLo
OXYCPHHq5blRvGxnz1qnmVPHyVEYVjdboJiavY1gbwtK+wCBPS85htaRuFxFb9LD
NO+F4qDaW22QCAuvcoMJMDE=
-----END PRIVATE KEY-----";

        const TEST_RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvb0EtMVFHWgpptjLmpMW
56FBkgs3ip7NBdwt8eyPwkrj1dXJHTyBnzqL3jbPpkhyOmeTMEeEryXMbsCWc/HZ
nfVFxy4a/0djKTgOXCzHUu2clXyq1AtG5b1rifVJ/DNjjZrcfey+nPZNO9Rw/TF/
TVSZbCijoRe4b7i/guVnPHVLBPE45x5GeKQkHBweXmNQRMx1wNLmak4LMuPmH6kP
XE+Dvlz1ZZzzxrsjXveBfzRqgx9KIH0I3PQBKj1bKzqMno2P6AR5sIUq3+3fJQ80
zejNikfS+pmVClGnwinccPXH8iP0UEaUKtEiumnjePyzogqb5YiPlOi33djLFq+0
/wIDAQAB
-----END PUBLIC KEY-----";

        const SECRET: &str = "test-hs256-secret";

        fn hs256_cfg() -> AuthConfig {
            AuthConfig::Jwt {
                signing_method: g2_core::JwtSigningMethod::Hs256,
                secret: Some(SECRET.into()),
                public_key_pem: None,
                header: "Authorization".into(),
                identity_claim: "sub".into(),
            }
        }

        fn hs256_token(claims: &serde_json::Value) -> String {
            encode(
                &Header::default(),
                claims,
                &EncodingKey::from_secret(SECRET.as_bytes()),
            )
            .expect("encode hs256")
        }

        fn future_exp() -> u64 {
            unix_now_secs() + 3600
        }

        async fn call(cfg: &AuthConfig, token: &str) -> Response<ProxyBody> {
            let mut req = request("/x");
            req.headers_mut().insert(
                "authorization",
                format!("Bearer {token}").parse().expect("value"),
            );
            service(cfg, MemoryStorage::new())
                .oneshot(req)
                .await
                .expect("infallible")
        }

        #[tokio::test]
        async fn valid_hs256_token_builds_session_from_claims() {
            let token = hs256_token(&serde_json::json!({
                "sub": "alice",
                "exp": future_exp(),
            }));
            let resp = call(&hs256_cfg(), &token).await;
            assert_eq!(resp.status(), StatusCode::OK);
            // `require_session` echoes the alias, which comes from `sub`.
            assert_eq!(
                resp.headers()
                    .get("x-echo-alias")
                    .expect("alias")
                    .as_bytes(),
                b"alice"
            );
        }

        #[tokio::test]
        async fn wrong_secret_expired_and_missing_identity_are_403() {
            let wrong_secret = encode(
                &Header::default(),
                &serde_json::json!({"sub": "alice", "exp": future_exp()}),
                &EncodingKey::from_secret(b"other-secret"),
            )
            .expect("encode");
            // Far enough in the past to clear the default validation leeway.
            let expired = hs256_token(&serde_json::json!({
                "sub": "alice",
                "exp": unix_now_secs() - 600,
            }));
            let no_identity = hs256_token(&serde_json::json!({"exp": future_exp()}));

            for (name, token) in [
                ("wrong secret", wrong_secret),
                ("expired", expired),
                ("no identity claim", no_identity),
            ] {
                let resp = call(&hs256_cfg(), &token).await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN, "case: {name}");
            }
        }

        #[tokio::test]
        async fn token_without_exp_is_rejected() {
            let token = hs256_token(&serde_json::json!({"sub": "alice"}));
            let resp = call(&hs256_cfg(), &token).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn missing_token_is_401() {
            let resp = service(&hs256_cfg(), MemoryStorage::new())
                .oneshot(request("/x"))
                .await
                .expect("infallible");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn rs256_round_trip_and_alg_confusion_rejected() {
            let cfg = AuthConfig::Jwt {
                signing_method: g2_core::JwtSigningMethod::Rs256,
                secret: None,
                public_key_pem: Some(TEST_RSA_PUBLIC_PEM.into()),
                header: "Authorization".into(),
                identity_claim: "sub".into(),
            };
            let claims = serde_json::json!({"sub": "bob", "exp": future_exp()});

            let rs256 = encode(
                &Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes()).expect("private key"),
            )
            .expect("encode rs256");
            let resp = call(&cfg, &rs256).await;
            assert_eq!(resp.status(), StatusCode::OK);

            // An HS256 token must not pass an RS256 API (alg confusion).
            let hs256 = hs256_token(&claims);
            let resp = call(&cfg, &hs256).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }

        #[test]
        fn invalid_pem_fails_layer_construction() {
            let cfg = AuthConfig::Jwt {
                signing_method: g2_core::JwtSigningMethod::Rs256,
                secret: None,
                public_key_pem: Some("not a pem".into()),
                header: "Authorization".into(),
                identity_claim: "sub".into(),
            };
            let err = AuthLayer::from_config(&cfg, Arc::new(MemoryStorage::new()), API, ORG);
            assert!(err.is_err());
        }
    }

    mod basic {
        use g2_core::BasicAuthData;

        use super::*;

        /// bcrypt cost for test hashes: the minimum, to keep tests fast.
        const TEST_COST: u32 = 4;

        fn basic_cfg() -> AuthConfig {
            AuthConfig::BasicAuth {
                realm: "g2way".into(),
            }
        }

        fn creds(user: &str, pass: &str) -> HeaderValue {
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            format!("Basic {encoded}").parse().expect("header value")
        }

        async fn seed_user(storage: &MemoryStorage, user: &str, pass: &str, session: KeySession) {
            let session = KeySession {
                basic_auth: Some(BasicAuthData {
                    password_hash: bcrypt::hash(pass, TEST_COST).expect("hash"),
                }),
                ..session
            };
            let key = session_storage_key(ORG, &hash_key(&format!("basic:{user}")));
            storage
                .set(&key, &serde_json::to_string(&session).expect("json"), None)
                .await
                .expect("seed");
        }

        async fn call(storage: MemoryStorage, auth: Option<HeaderValue>) -> Response<ProxyBody> {
            let mut req = request("/x");
            if let Some(value) = auth {
                req.headers_mut().insert("authorization", value);
            }
            service(&basic_cfg(), storage)
                .oneshot(req)
                .await
                .expect("infallible")
        }

        #[tokio::test]
        async fn valid_credentials_pass_with_session_context() {
            let storage = MemoryStorage::new();
            let session = KeySession {
                alias: Some("alice".into()),
                ..KeySession::default()
            };
            seed_user(&storage, "alice", "s3cret", session).await;

            let resp = call(storage, Some(creds("alice", "s3cret"))).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers()
                    .get("x-echo-alias")
                    .expect("alias")
                    .as_bytes(),
                b"alice"
            );
        }

        #[tokio::test]
        async fn missing_header_is_401_with_challenge() {
            let resp = call(MemoryStorage::new(), None).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                resp.headers()
                    .get(header::WWW_AUTHENTICATE)
                    .expect("challenge")
                    .as_bytes(),
                b"Basic realm=\"g2way\""
            );
        }

        #[tokio::test]
        async fn unparseable_credentials_are_401() {
            let cases: [(&str, HeaderValue); 4] = [
                ("bearer scheme", "Bearer abc".parse().expect("value")),
                (
                    "bad base64",
                    "Basic !!!not-base64!!!".parse().expect("value"),
                ),
                (
                    "no colon",
                    format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode("no-colon-here")
                    )
                    .parse()
                    .expect("value"),
                ),
                ("empty username", creds("", "password")),
            ];
            for (name, value) in cases {
                let resp = call(MemoryStorage::new(), Some(value)).await;
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "case: {name}");
                assert!(
                    resp.headers().contains_key(header::WWW_AUTHENTICATE),
                    "case {name}: challenge header missing"
                );
            }
        }

        #[tokio::test]
        async fn unknown_user_and_wrong_password_are_403() {
            let storage = MemoryStorage::new();
            seed_user(&storage, "alice", "s3cret", KeySession::default()).await;

            let resp = call(storage.clone(), Some(creds("mallory", "s3cret"))).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "unknown user");

            let resp = call(storage, Some(creds("alice", "wrong"))).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "wrong password");
        }

        #[tokio::test]
        async fn session_without_basic_auth_data_is_403() {
            let storage = MemoryStorage::new();
            // Seeded directly (not via seed_user): no basic_auth data.
            let key = session_storage_key(ORG, &hash_key("basic:alice"));
            storage
                .set(
                    &key,
                    &serde_json::to_string(&KeySession::default()).expect("json"),
                    None,
                )
                .await
                .expect("seed");

            let resp = call(storage, Some(creds("alice", "anything"))).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn inactive_expired_and_unauthorized_api_are_403() {
            let storage = MemoryStorage::new();
            seed_user(
                &storage,
                "inactive",
                "pw",
                KeySession {
                    active: false,
                    ..KeySession::default()
                },
            )
            .await;
            seed_user(
                &storage,
                "expired",
                "pw",
                KeySession {
                    expires_at: Some(1), // 1970: long past
                    ..KeySession::default()
                },
            )
            .await;
            seed_user(
                &storage,
                "other-api",
                "pw",
                KeySession {
                    access: [("not-this-api".to_owned(), Default::default())].into(),
                    ..KeySession::default()
                },
            )
            .await;

            for user in ["inactive", "expired", "other-api"] {
                let resp = call(storage.clone(), Some(creds(user, "pw"))).await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN, "user `{user}`");
            }
        }

        #[tokio::test]
        async fn password_containing_colon_works() {
            let storage = MemoryStorage::new();
            seed_user(&storage, "alice", "pa:ss:word", KeySession::default()).await;
            let resp = call(storage, Some(creds("alice", "pa:ss:word"))).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn malformed_stored_password_hash_is_500() {
            let storage = MemoryStorage::new();
            let session = KeySession {
                basic_auth: Some(BasicAuthData {
                    password_hash: "not-a-bcrypt-hash".into(),
                }),
                ..KeySession::default()
            };
            let key = session_storage_key(ORG, &hash_key("basic:alice"));
            storage
                .set(&key, &serde_json::to_string(&session).expect("json"), None)
                .await
                .expect("seed");

            let resp = call(storage, Some(creds("alice", "anything"))).await;
            assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }

        #[test]
        fn dummy_hash_is_well_formed_and_matches_nothing() {
            assert!(!bcrypt::verify("x", DUMMY_BCRYPT_HASH).expect("well-formed hash"));
        }

        #[test]
        fn basic_stripping_rules() {
            assert_eq!(strip_basic("Basic abc"), Some("abc"));
            assert_eq!(strip_basic("BASIC  abc"), Some("abc"));
            assert_eq!(strip_basic("basic"), None); // no space: not a scheme
            assert_eq!(strip_basic("Bearer abc"), None);
            assert_eq!(strip_basic("Basicabc"), None);
        }
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
