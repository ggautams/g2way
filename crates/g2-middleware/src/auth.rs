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
//!   against a static key (HS256 secret or RS256 public key) or, with
//!   `jwks_url`, against a key set fetched from the identity provider and
//!   cached pod-locally (see [`jwks`](crate::jwks)). Its claims are turned
//!   into an ephemeral session: no storage lookup, `expires_at` from `exp`,
//!   alias from the identity claim, access restricted to this API.
//! - **`basic_auth`** — RFC 7617 `Authorization: Basic base64(user:pass)`.
//!   The username (hashed under a `basic:` namespace) resolves to a stored
//!   session whose `basic_auth.password_hash` the presented password is
//!   bcrypt-verified against. Verification runs on the blocking pool
//!   (bcrypt costs ~100ms by design); per-user verification caching is a
//!   possible later optimization, deliberately not built yet.
//! - **`mtls`** — the client certificate verified by the TLS handshake is
//!   the credential; the accept loop stamps its SHA-256 fingerprint into
//!   the request's [`ConnectionInfo`](crate::ConnectionInfo) extension.
//!   The fingerprint (hashed under an `mtls:` namespace, like basic auth's
//!   usernames) resolves to a stored session — so a certificate the CA
//!   signed but nobody provisioned is still rejected. Requires the gateway
//!   listener to terminate TLS with `client_cert_mode: optional` or
//!   `required` (see `docs/tls.md`).
//!
//! Stored sessions referencing a policy (`apply_policies`) get the
//! policy's rate/quota/access applied before the access check — one extra
//! storage `GET`, only for keys that reference one. (A session/policy
//! read-through cache is a possible later optimization, deliberately not
//! built yet.)
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
//!   `WWW-Authenticate: Basic realm="…"` challenge. For mtls: the
//!   connection carried no verified client certificate (a plaintext
//!   listener, or `client_cert_mode: optional` with a certificate-less
//!   client).
//! - `403` — token unknown or fails verification, wrong password, session
//!   inactive/expired, the session does not grant this API, or its policy
//!   is missing or inactive. One message for all of these: which one it
//!   was must not leak to the caller (details are logged). Unknown
//!   basic-auth users still cost one bcrypt verify (against a dummy hash)
//!   so response timing does not reveal whether a username exists.
//! - `503` — the storage backend errored; the request may be retried.
//! - `500` — the stored session or policy record is corrupt (not valid
//!   JSON, disagrees with its storage key, references multiple policies)
//!   or a stored bcrypt hash is malformed (operational bugs, logged
//!   loudly).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use g2_core::api_definition::DEFAULT_JWKS_REFRESH_SECS;
use g2_core::policy::policy_storage_key;
use g2_core::session::{hash_key, session_storage_key};
use g2_core::{AuthConfig, Error, JwtSigningMethod, KeySession, Policy};
use g2_storage::SharedStorage;
use http::header::{HeaderName, HeaderValue};
use http::{header, Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use tower::{Layer, Service};

use crate::context::SessionContext;
use crate::jwks::{JwksCache, SharedJwksFetch};
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
    /// `jwt`: verify the bearer token against the configured key source.
    Jwt {
        /// Header carrying the JWT.
        header: HeaderName,
        keys: JwtKeys,
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
    /// `mtls`: resolve the handshake-verified client-certificate
    /// fingerprint (from the request's `ConnectionInfo` extension) in
    /// storage.
    Mtls { storage: SharedStorage },
}

/// Where the JWT mode's verification keys come from.
enum JwtKeys {
    /// A single key fixed at config-load time (HS256 secret or RS256 PEM).
    Static(Box<DecodingKey>),
    /// Keys fetched from `jwks_url`, selected per token by `kid`.
    Jwks(Arc<JwksCache>),
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = match &self.mode {
            Mode::Token { .. } => "token",
            Mode::Jwt { .. } => "jwt",
            Mode::Basic { .. } => "basic",
            Mode::Mtls { .. } => "mtls",
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
    /// `jwks_fetcher` supplies the HTTP client used when the JWT mode sets
    /// `jwks_url`; the proxy passes its shared upstream client, and callers
    /// building configs that never use JWKS may pass `None`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] if the configured header name
    /// is invalid (normally caught earlier by definition validation), or if
    /// `jwks_url` is set while `jwks_fetcher` is `None`.
    pub fn from_config(
        cfg: &AuthConfig,
        storage: SharedStorage,
        api_id: &str,
        org_id: &str,
        jwks_fetcher: Option<SharedJwksFetch>,
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
                jwks_url,
                jwks_refresh_secs,
                header,
                identity_claim,
            } => {
                let (algorithm, keys) = match (signing_method, jwks_url) {
                    (JwtSigningMethod::Hs256, _) => {
                        let secret = secret
                            .as_deref()
                            .ok_or_else(|| invalid("hs256 requires `auth.secret`".into()))?;
                        (
                            Algorithm::HS256,
                            JwtKeys::Static(Box::new(DecodingKey::from_secret(secret.as_bytes()))),
                        )
                    }
                    (JwtSigningMethod::Rs256, None) => {
                        let pem = public_key_pem.as_deref().ok_or_else(|| {
                            invalid("rs256 requires `auth.public_key_pem`".into())
                        })?;
                        let key = DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
                            invalid(format!("`auth.public_key_pem` is not a valid RSA PEM: {e}"))
                        })?;
                        (Algorithm::RS256, JwtKeys::Static(Box::new(key)))
                    }
                    (JwtSigningMethod::Rs256, Some(url)) => {
                        let fetcher = jwks_fetcher.ok_or_else(|| {
                            invalid(
                                "`auth.jwks_url` is set but no JWKS fetcher is available".into(),
                            )
                        })?;
                        let cache = Arc::new(JwksCache::new(api_id, url.clone(), fetcher));
                        let interval = Duration::from_secs(
                            jwks_refresh_secs.unwrap_or(DEFAULT_JWKS_REFRESH_SECS),
                        );
                        // The route's AuthState Arc keeps the cache alive; a
                        // config reload drops it and the task self-exits.
                        JwksCache::spawn_refresher(&cache, interval);
                        (Algorithm::RS256, JwtKeys::Jwks(cache))
                    }
                };
                // `exp` is required and validated (with the library's default
                // leeway); tokens without an expiry are rejected.
                let validation = Validation::new(algorithm);
                Mode::Jwt {
                    header: parse_header(header)?,
                    keys,
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
            AuthConfig::Mtls {} => Mode::Mtls { storage },
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

        // An `ignore_auth_paths` match (stamped by the path-policy layer
        // above) forwards without authenticating: no SessionContext, so the
        // rate-limit layer below passes the request through untouched too.
        if req
            .extensions()
            .get::<crate::context::AuthBypass>()
            .is_some()
        {
            return Box::pin(async move { inner.call(req).await });
        }

        Box::pin(async move {
            match authenticate(&state, &req).await {
                Ok(session_ctx) => {
                    // Surface the key's alias on the request span (a no-op
                    // when the chain has no TraceLayer).
                    if let Some(alias) = session_ctx.session().alias.as_deref() {
                        tracing::Span::current().record(crate::trace::KEY_ALIAS_FIELD, alias);
                    }
                    req.extensions_mut().insert(session_ctx.clone());
                    let mut resp = inner.call(req).await?;
                    // Also stamp the session onto the response, for layers
                    // above auth (analytics) that never see the request
                    // extensions. Cheap: SessionContext is Arc-backed.
                    resp.extensions_mut().insert(session_ctx);
                    Ok(resp)
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
            keys,
            validation,
            identity_claim,
        } => {
            let token = extract_token(header, None, None, req).ok_or_else(|| {
                json_error(StatusCode::UNAUTHORIZED, "authorization field missing")
            })?;
            match keys {
                JwtKeys::Static(key) => {
                    authenticate_jwt(state, key, validation, identity_claim, &token)
                }
                JwtKeys::Jwks(cache) => {
                    let key = resolve_jwks_key(state, cache, &token).await?;
                    authenticate_jwt(state, &key, validation, identity_claim, &token)
                }
            }
        }
        Mode::Basic { challenge, storage } => {
            authenticate_basic(state, storage, challenge, req).await
        }
        Mode::Mtls { storage } => {
            // The fingerprint only ever comes from the accept loop's
            // ConnectionInfo — never from anything the client sends inside
            // the request — so it is already handshake-verified.
            let fingerprint = req
                .extensions()
                .get::<crate::ConnectionInfo>()
                .and_then(|conn| conn.client_cert_fingerprint.clone())
                .ok_or_else(|| {
                    json_error(StatusCode::UNAUTHORIZED, "client certificate required")
                })?;
            // Namespaced like basic auth's `basic:{username}` so a raw API
            // key can never collide with a certificate identity.
            authenticate_stored_token(state, storage, &format!("mtls:{fingerprint}")).await
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

    let Some(session) = session else {
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    };
    if !(password_matches
        && session.basic_auth.is_some()
        && session.active
        && !session.is_expired(unix_now_secs()))
    {
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    }
    // Policy resolution must precede the access check: the policy's ACL
    // replaces the session's own.
    let session = resolve_policy(state, storage, session).await?;
    if !session.allows_api(&state.api_id) {
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    }
    Ok(SessionContext::new(session, key_hash))
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

    if !session.active || session.is_expired(unix_now_secs()) {
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    }
    // Policy resolution must precede the access check: the policy's ACL
    // replaces the session's own. Dead keys were rejected above without
    // paying for the policy lookup.
    let session = resolve_policy(state, storage, session).await?;
    if !session.allows_api(&state.api_id) {
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    }
    Ok(SessionContext::new(session, key_hash))
}

/// Applies the session's referenced policy, if any (see
/// [`KeySession::apply_policies`] and [`Policy`]): fetches it from storage
/// and replaces the session's rate/quota/access with the policy's.
///
/// Rejections mirror the session-lookup contract: a key referencing a
/// missing or inactive policy gets the standard no-oracle 403 (details are
/// logged — both are operator states, a kill switch or a dangling
/// reference); a corrupt or misfiled policy record is a 500; storage
/// failure is a 503.
async fn resolve_policy(
    state: &AuthState,
    storage: &SharedStorage,
    mut session: KeySession,
) -> Result<KeySession, Response<ProxyBody>> {
    // Sessions are validated to at most one policy on write; a stored
    // record violating that is treated like any other corrupt record.
    let policy_id = match session.apply_policies.as_slice() {
        [] => return Ok(session),
        [policy_id] => policy_id,
        more => {
            tracing::error!(
                api_id = %state.api_id,
                count = more.len(),
                "stored key session references multiple policies (unsupported)"
            );
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "malformed key session record",
            ));
        }
    };

    let storage_key = policy_storage_key(&session.org_id, policy_id);
    let record = storage.get(&storage_key).await.map_err(|e| {
        tracing::error!(api_id = %state.api_id, error = %e, "policy storage lookup failed");
        json_error(StatusCode::SERVICE_UNAVAILABLE, "key storage unavailable")
    })?;
    let Some(record) = record else {
        tracing::error!(
            api_id = %state.api_id,
            policy_id,
            "key session references a policy that does not exist"
        );
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    };
    let policy: Policy = serde_json::from_str(&record).map_err(|e| {
        tracing::error!(policy_id, error = %e, "stored policy is not valid JSON");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, "malformed policy record")
    })?;
    if policy.org_id != session.org_id || policy.policy_id != *policy_id {
        tracing::error!(
            policy_id,
            record_policy_id = %policy.policy_id,
            record_org_id = %policy.org_id,
            "stored policy record does not match its storage key"
        );
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "malformed policy record",
        ));
    }
    if !policy.active {
        tracing::debug!(api_id = %state.api_id, policy_id, "policy is inactive; rejecting key");
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    }

    session.apply_policy(&policy);
    Ok(session)
}

/// `jwt` mode with `jwks_url`: resolve the token's `kid` to a cached JWKS
/// key, refetching (cooldown-gated) on an unknown kid.
///
/// Every failure — unparseable header, missing `kid`, no matching key even
/// after a refetch — is the shared no-oracle 403.
async fn resolve_jwks_key(
    state: &AuthState,
    cache: &JwksCache,
    token: &str,
) -> Result<DecodingKey, Response<ProxyBody>> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| {
        tracing::debug!(api_id = %state.api_id, error = %e, "JWT header unparseable");
        json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG)
    })?;
    let Some(kid) = header.kid else {
        tracing::debug!(
            api_id = %state.api_id,
            "JWT has no kid; jwks mode requires one"
        );
        return Err(json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG));
    };
    cache.key_for(&kid).await.ok_or_else(|| {
        tracing::debug!(api_id = %state.api_id, kid, "no JWKS key matches the token's kid");
        json_error(StatusCode::FORBIDDEN, FORBIDDEN_MSG)
    })
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
        // Lets policy tests observe the effective (post-policy) rate.
        if let Some(rate) = &ctx.session().rate {
            resp.headers_mut().insert(
                "x-echo-rate",
                http::HeaderValue::from_str(&format!("{}/{}", rate.requests, rate.per_seconds))
                    .expect("rate"),
            );
        }
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
        let layer = AuthLayer::from_config(cfg, Arc::new(storage), API, ORG, None)
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
            None,
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

    /// A fingerprint as the accept loop would compute it (any hex string
    /// works for the middleware; real digests are an accept-loop concern).
    const FP: &str = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";

    fn mtls_request(fingerprint: Option<&str>) -> Request<ProxyBody> {
        let mut req = request("/x");
        req.extensions_mut().insert(crate::ConnectionInfo {
            tls: true,
            client_cert_fingerprint: fingerprint.map(Into::into),
        });
        req
    }

    #[tokio::test]
    async fn mtls_without_connection_info_is_401() {
        // A plaintext listener never stamps ConnectionInfo at all.
        let svc = service(&AuthConfig::Mtls {}, MemoryStorage::new());
        let resp = svc.oneshot(request("/x")).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mtls_without_client_cert_is_401() {
        // `client_cert_mode: optional` admits certificate-less connections;
        // an mtls-mode API must still turn them away.
        let svc = service(&AuthConfig::Mtls {}, MemoryStorage::new());
        let resp = svc.oneshot(mtls_request(None)).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mtls_unprovisioned_cert_is_403() {
        // CA-signed (the handshake passed) but nobody provisioned it.
        let svc = service(&AuthConfig::Mtls {}, MemoryStorage::new());
        let resp = svc
            .oneshot(mtls_request(Some(FP)))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mtls_provisioned_cert_passes_with_session_context() {
        let storage = MemoryStorage::new();
        let session = KeySession {
            alias: Some("billing-service".into()),
            ..KeySession::default()
        };
        seed(&storage, &format!("mtls:{FP}"), &session).await;

        let svc = service(&AuthConfig::Mtls {}, storage);
        let resp = svc
            .oneshot(mtls_request(Some(FP)))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-echo-alias")
                .expect("alias")
                .as_bytes(),
            b"billing-service"
        );
    }

    #[tokio::test]
    async fn mtls_inactive_or_misscoped_session_is_403() {
        let storage = MemoryStorage::new();
        let inactive = KeySession {
            active: false,
            ..KeySession::default()
        };
        seed(&storage, &format!("mtls:{FP}"), &inactive).await;
        let resp = service(&AuthConfig::Mtls {}, storage.clone())
            .oneshot(mtls_request(Some(FP)))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "inactive session");

        let elsewhere = KeySession {
            access: std::iter::once(("some-other-api".to_owned(), Default::default())).collect(),
            ..KeySession::default()
        };
        seed(&storage, &format!("mtls:{FP}"), &elsewhere).await;
        let resp = service(&AuthConfig::Mtls {}, storage)
            .oneshot(mtls_request(Some(FP)))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "ACL without this API");
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

    mod policy {
        use g2_core::session::RateLimit;

        use super::*;

        async fn seed_policy(storage: &MemoryStorage, policy: &Policy) {
            storage
                .set(
                    &policy_storage_key(&policy.org_id, &policy.policy_id),
                    &serde_json::to_string(policy).expect("json"),
                    None,
                )
                .await
                .expect("seed policy");
        }

        fn policy(policy_id: &str, access_api: Option<&str>) -> Policy {
            Policy {
                policy_id: policy_id.into(),
                name: policy_id.into(),
                org_id: ORG.into(),
                active: true,
                rate: Some(RateLimit {
                    requests: 100,
                    per_seconds: 60,
                }),
                quota: None,
                access: access_api
                    .map(|api| [(api.to_owned(), Default::default())].into())
                    .unwrap_or_default(),
            }
        }

        fn session_with_policy(policy_id: &str) -> KeySession {
            KeySession {
                // Deliberately restrictive on their own: the policy must
                // replace both.
                rate: Some(RateLimit {
                    requests: 1,
                    per_seconds: 1,
                }),
                access: [("some-other-api".to_owned(), Default::default())].into(),
                apply_policies: vec![policy_id.into()],
                ..KeySession::default()
            }
        }

        async fn call(storage: MemoryStorage, token: &str) -> Response<ProxyBody> {
            let mut req = request("/x");
            req.headers_mut()
                .insert("authorization", token.parse().expect("value"));
            service(&token_cfg(None, None), storage)
                .oneshot(req)
                .await
                .expect("infallible")
        }

        #[tokio::test]
        async fn policy_replaces_session_access_and_rate() {
            let storage = MemoryStorage::new();
            seed(&storage, "k", &session_with_policy("gold")).await;
            // The session's own ACL does not grant this API; the policy's
            // does — and its rate must win too.
            seed_policy(&storage, &policy("gold", Some(API))).await;

            let resp = call(storage, "k").await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers().get("x-echo-rate").expect("rate").as_bytes(),
                b"100/60"
            );
        }

        #[tokio::test]
        async fn policy_can_revoke_access_the_session_would_have_had() {
            let storage = MemoryStorage::new();
            // Session with an empty ACL (= every API) but a policy scoped
            // to a different API: the policy's ACL replaces, so 403.
            let session = KeySession {
                apply_policies: vec!["scoped".into()],
                ..KeySession::default()
            };
            seed(&storage, "k", &session).await;
            seed_policy(&storage, &policy("scoped", Some("not-this-api"))).await;

            let resp = call(storage, "k").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn missing_and_inactive_policies_are_403() {
            let storage = MemoryStorage::new();
            seed(&storage, "dangling", &session_with_policy("nonexistent")).await;

            seed(&storage, "killed", &session_with_policy("off")).await;
            let mut off = policy("off", Some(API));
            off.active = false;
            seed_policy(&storage, &off).await;

            for token in ["dangling", "killed"] {
                let resp = call(storage.clone(), token).await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN, "token `{token}`");
            }
        }

        #[tokio::test]
        async fn corrupt_and_misfiled_policy_records_are_500() {
            let storage = MemoryStorage::new();
            seed(&storage, "corrupt", &session_with_policy("broken")).await;
            storage
                .set(&policy_storage_key(ORG, "broken"), "not json", None)
                .await
                .expect("seed");

            seed(&storage, "misfiled", &session_with_policy("claimed")).await;
            // A valid policy stored under a key naming a different policy_id.
            seed_policy(
                &storage,
                &Policy {
                    policy_id: "claimed".into(),
                    ..policy("actual", Some(API))
                },
            )
            .await;
            // seed_policy keys by the record's own id; re-file it under the
            // referenced id with a mismatched body.
            let record = storage
                .get(&policy_storage_key(ORG, "claimed"))
                .await
                .expect("get")
                .expect("seeded");
            let record = record.replace("\"claimed\"", "\"actual\"");
            storage
                .set(&policy_storage_key(ORG, "claimed"), &record, None)
                .await
                .expect("re-file");

            for token in ["corrupt", "misfiled"] {
                let resp = call(storage.clone(), token).await;
                assert_eq!(
                    resp.status(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "token `{token}`"
                );
            }
        }

        #[tokio::test]
        async fn stored_session_with_multiple_policies_is_500() {
            let storage = MemoryStorage::new();
            // Bypasses validate() the way a hand-written record could.
            let session = KeySession {
                apply_policies: vec!["a".into(), "b".into()],
                ..KeySession::default()
            };
            seed(&storage, "multi", &session).await;

            let resp = call(storage, "multi").await;
            assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }

        #[tokio::test]
        async fn basic_auth_sessions_resolve_policies_too() {
            use g2_core::BasicAuthData;

            let storage = MemoryStorage::new();
            let session = KeySession {
                basic_auth: Some(BasicAuthData {
                    password_hash: bcrypt::hash("pw", 4).expect("hash"),
                }),
                access: [("some-other-api".to_owned(), Default::default())].into(),
                apply_policies: vec!["gold".into()],
                ..KeySession::default()
            };
            let key = session_storage_key(ORG, &hash_key("basic:alice"));
            storage
                .set(&key, &serde_json::to_string(&session).expect("json"), None)
                .await
                .expect("seed");
            seed_policy(&storage, &policy("gold", Some(API))).await;

            let cfg = AuthConfig::BasicAuth {
                realm: "g2way".into(),
            };
            let mut req = request("/x");
            let encoded = base64::engine::general_purpose::STANDARD.encode("alice:pw");
            req.headers_mut().insert(
                "authorization",
                format!("Basic {encoded}").parse().expect("value"),
            );
            let resp = service(&cfg, storage)
                .oneshot(req)
                .await
                .expect("infallible");
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers().get("x-echo-rate").expect("rate").as_bytes(),
                b"100/60"
            );
        }
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
                jwks_url: None,
                jwks_refresh_secs: None,
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
                jwks_url: None,
                jwks_refresh_secs: None,
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
                jwks_url: None,
                jwks_refresh_secs: None,
                header: "Authorization".into(),
                identity_claim: "sub".into(),
            };
            let err = AuthLayer::from_config(&cfg, Arc::new(MemoryStorage::new()), API, ORG, None);
            assert!(err.is_err());
        }

        mod jwks {
            use super::*;
            use crate::jwks::test_support::FakeFetch;

            /// Base64url modulus of [`TEST_RSA_PUBLIC_PEM`]; pasted once and
            /// drift-guarded by `jwk_material_matches_the_test_rsa_pem`.
            const TEST_RSA_N: &str = "vb0EtMVFHWgpptjLmpMW56FBkgs3ip7NBdwt8eyPwkrj1dXJHTyBnzqL3jbPpkhyOmeTMEeEryXMbsCWc_HZnfVFxy4a_0djKTgOXCzHUu2clXyq1AtG5b1rifVJ_DNjjZrcfey-nPZNO9Rw_TF_TVSZbCijoRe4b7i_guVnPHVLBPE45x5GeKQkHBweXmNQRMx1wNLmak4LMuPmH6kPXE-Dvlz1ZZzzxrsjXveBfzRqgx9KIH0I3PQBKj1bKzqMno2P6AR5sIUq3-3fJQ80zejNikfS-pmVClGnwinccPXH8iP0UEaUKtEiumnjePyzogqb5YiPlOi33djLFq-0_w";

            fn jwks_json(kid: &str) -> String {
                format!(
                    r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{TEST_RSA_N}","e":"AQAB"}}]}}"#
                )
            }

            fn rs256_token(kid: &str, claims: &serde_json::Value) -> String {
                let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
                header.kid = Some(kid.into());
                encode(
                    &header,
                    claims,
                    &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes())
                        .expect("private key"),
                )
                .expect("encode rs256")
            }

            fn cache(fetch: &Arc<FakeFetch>) -> Arc<JwksCache> {
                Arc::new(JwksCache::new(
                    API,
                    "http://idp.internal/jwks.json".into(),
                    Arc::clone(fetch) as SharedJwksFetch,
                ))
            }

            /// Builds a JWKS-mode service directly around `cache`, bypassing
            /// `from_config` so tests never race the background refresher:
            /// every fetch happens through the deterministic on-miss path.
            fn jwks_service(cache: &Arc<JwksCache>) -> crate::ChainService {
                let layer = AuthLayer {
                    state: Arc::new(AuthState {
                        api_id: API.into(),
                        org_id: ORG.into(),
                        mode: Mode::Jwt {
                            header: HeaderName::from_static("authorization"),
                            keys: JwtKeys::Jwks(Arc::clone(cache)),
                            validation: Box::new(Validation::new(Algorithm::RS256)),
                            identity_claim: "sub".into(),
                        },
                    }),
                };
                crate::ChainService::new(layer.layer(tower::service_fn(require_session)))
            }

            async fn call_jwks(cache: &Arc<JwksCache>, token: &str) -> Response<ProxyBody> {
                let mut req = request("/x");
                req.headers_mut().insert(
                    "authorization",
                    format!("Bearer {token}").parse().expect("value"),
                );
                jwks_service(cache).oneshot(req).await.expect("infallible")
            }

            fn claims() -> serde_json::Value {
                serde_json::json!({"sub": "carol", "exp": future_exp()})
            }

            #[test]
            fn jwk_material_matches_the_test_rsa_pem() {
                let set: jsonwebtoken::jwk::JwkSet =
                    serde_json::from_str(&jwks_json("k1")).expect("valid JWKS");
                let jwk = set.find("k1").expect("k1 present");
                let key = DecodingKey::from_jwk(jwk).expect("usable key");
                let token = rs256_token("k1", &claims());
                jsonwebtoken::decode::<serde_json::Value>(
                    &token,
                    &key,
                    &Validation::new(Algorithm::RS256),
                )
                .expect("the pasted JWK matches TEST_RSA_PUBLIC_PEM");
            }

            #[tokio::test]
            async fn jwks_config_verifies_tokens_through_from_config() {
                let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
                let cfg = AuthConfig::Jwt {
                    signing_method: g2_core::JwtSigningMethod::Rs256,
                    secret: None,
                    public_key_pem: None,
                    jwks_url: Some("http://idp.internal/jwks.json".into()),
                    jwks_refresh_secs: None,
                    header: "Authorization".into(),
                    identity_claim: "sub".into(),
                };
                let layer = AuthLayer::from_config(
                    &cfg,
                    Arc::new(MemoryStorage::new()),
                    API,
                    ORG,
                    Some(Arc::clone(&fetch) as SharedJwksFetch),
                )
                .expect("valid cfg")
                .expect("jwt mode");
                let svc = crate::ChainService::new(layer.layer(tower::service_fn(require_session)));
                let mut req = request("/x");
                req.headers_mut().insert(
                    "authorization",
                    format!("Bearer {}", rs256_token("k1", &claims()))
                        .parse()
                        .expect("value"),
                );
                let resp = svc.oneshot(req).await.expect("infallible");
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(
                    resp.headers()
                        .get("x-echo-alias")
                        .expect("alias")
                        .as_bytes(),
                    b"carol"
                );
            }

            #[tokio::test]
            async fn rotated_kid_is_picked_up_by_a_refetch() {
                let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
                let cache = cache(&fetch);
                let resp = call_jwks(&cache, &rs256_token("k1", &claims())).await;
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(fetch.calls(), 1);

                // The IdP rotates to k2; the next unknown-kid miss refetches.
                fetch.set_body(Ok(&jwks_json("k2")));
                cache.reset_miss_cooldown();
                let resp = call_jwks(&cache, &rs256_token("k2", &claims())).await;
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(fetch.calls(), 2);
            }

            #[tokio::test]
            async fn unknown_kid_is_403_and_the_cooldown_limits_refetches() {
                let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
                let cache = cache(&fetch);
                let resp = call_jwks(&cache, &rs256_token("ghost", &claims())).await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
                assert_eq!(fetch.calls(), 1, "the miss refetched once");

                // A second garbage kid inside the cooldown costs no fetch.
                let resp = call_jwks(&cache, &rs256_token("ghost2", &claims())).await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
                assert_eq!(fetch.calls(), 1, "cooldown holds");
            }

            #[tokio::test]
            async fn unreachable_jwks_endpoint_is_403_until_it_recovers() {
                let fetch = FakeFetch::new(Err("connection refused"));
                let cache = cache(&fetch);
                let token = rs256_token("k1", &claims());
                let resp = call_jwks(&cache, &token).await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);

                fetch.set_body(Ok(&jwks_json("k1")));
                cache.reset_miss_cooldown();
                let resp = call_jwks(&cache, &token).await;
                assert_eq!(resp.status(), StatusCode::OK);
            }

            #[tokio::test]
            async fn token_without_kid_is_403_without_fetching() {
                let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
                let cache = cache(&fetch);
                let token = encode(
                    &Header::new(jsonwebtoken::Algorithm::RS256),
                    &claims(),
                    &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes())
                        .expect("private key"),
                )
                .expect("encode");
                let resp = call_jwks(&cache, &token).await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
                assert_eq!(fetch.calls(), 0, "no kid, no lookup, no fetch");
            }

            #[tokio::test]
            async fn hs256_token_with_matching_kid_is_rejected() {
                // Alg confusion: even when the kid resolves to a key, the
                // layer's RS256-only validation rejects an HS256 signature.
                let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
                let cache = cache(&fetch);
                let header = Header {
                    kid: Some("k1".into()),
                    ..Header::default()
                };
                let token = encode(
                    &header,
                    &claims(),
                    &EncodingKey::from_secret(SECRET.as_bytes()),
                )
                .expect("encode hs256");
                let resp = call_jwks(&cache, &token).await;
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            }

            #[test]
            fn jwks_url_without_a_fetcher_fails_layer_construction() {
                let cfg = AuthConfig::Jwt {
                    signing_method: g2_core::JwtSigningMethod::Rs256,
                    secret: None,
                    public_key_pem: None,
                    jwks_url: Some("http://idp.internal/jwks.json".into()),
                    jwks_refresh_secs: None,
                    header: "Authorization".into(),
                    identity_claim: "sub".into(),
                };
                let err =
                    AuthLayer::from_config(&cfg, Arc::new(MemoryStorage::new()), API, ORG, None);
                assert!(err.is_err());
            }
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
