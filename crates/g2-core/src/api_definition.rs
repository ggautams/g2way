//! The [`ApiDefinition`] model: one upstream API exposed through the gateway.

use http::Uri;
use serde::{Deserialize, Serialize};

use crate::endpoints::{MockResponse, PathRule};
use crate::transform::{self, HeaderTransforms, UrlRewriteRule};
use crate::Error;

/// The organization id used while g2way runs in single-organization mode.
pub const DEFAULT_ORG_ID: &str = "default";

fn default_org_id() -> String {
    DEFAULT_ORG_ID.to_owned()
}

fn default_true() -> bool {
    true
}

/// Default upstream timeout applied when a definition does not specify one.
const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 30_000;

fn default_upstream_timeout_ms() -> u64 {
    DEFAULT_UPSTREAM_TIMEOUT_MS
}

/// Header the auth-token mode reads when a definition does not name one.
pub const DEFAULT_AUTH_HEADER: &str = "Authorization";

fn default_auth_header() -> String {
    DEFAULT_AUTH_HEADER.to_owned()
}

/// Claim the JWT mode uses as the caller identity when none is configured.
pub const DEFAULT_IDENTITY_CLAIM: &str = "sub";

fn default_identity_claim() -> String {
    DEFAULT_IDENTITY_CLAIM.to_owned()
}

/// Realm the basic-auth mode advertises in `WWW-Authenticate` challenges
/// when a definition does not name one.
pub const DEFAULT_BASIC_AUTH_REALM: &str = "g2way";

fn default_basic_auth_realm() -> String {
    DEFAULT_BASIC_AUTH_REALM.to_owned()
}

/// JWT signature algorithms supported by [`AuthConfig::Jwt`].
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JwtSigningMethod {
    /// HMAC-SHA256 with a shared secret.
    Hs256,
    /// RSA-SHA256 with a public key.
    Rs256,
}

/// How clients authenticate to one API.
///
/// The default is [`AuthConfig::AuthToken`] reading the `Authorization`
/// header: an API is protected unless its definition **explicitly** opts out
/// with `{"auth": {"mode": "keyless"}}`. Forgetting to configure auth must
/// never silently expose an upstream.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AuthConfig {
    /// No authentication: every request is forwarded. Explicit opt-out.
    Keyless,

    /// Bearer/API-token auth: the token is looked up (hashed) in storage and
    /// must resolve to a live [`KeySession`](crate::KeySession).
    ///
    /// The token is searched in `header` first, then `query_param`, then
    /// `cookie` (each only if configured).
    AuthToken {
        /// Request header carrying the token. A `Bearer ` prefix, if present,
        /// is stripped.
        #[serde(default = "default_auth_header")]
        header: String,

        /// Optional query parameter also accepted as a token carrier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query_param: Option<String>,

        /// Optional cookie name also accepted as a token carrier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cookie: Option<String>,
    },

    /// JWT bearer auth: the token in `header` is verified against a static
    /// key and its claims are turned into an ephemeral session (no storage
    /// lookup). `jwks_url` fetching arrives in a later task.
    Jwt {
        /// Signature algorithm the tokens must use.
        signing_method: JwtSigningMethod,

        /// Shared secret for [`JwtSigningMethod::Hs256`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<String>,

        /// PEM-encoded RSA public key for [`JwtSigningMethod::Rs256`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key_pem: Option<String>,

        /// Request header carrying the JWT (a `Bearer ` prefix is stripped).
        #[serde(default = "default_auth_header")]
        header: String,

        /// Claim used as the caller identity (session alias and rate-limit
        /// key). Defaults to `sub`.
        #[serde(default = "default_identity_claim")]
        identity_claim: String,
    },

    /// HTTP Basic auth (RFC 7617): `Authorization: Basic base64(user:pass)`.
    ///
    /// The username resolves (hashed, under a `basic:` namespace) to a
    /// stored [`KeySession`](crate::KeySession) whose
    /// [`basic_auth`](crate::session::BasicAuthData) data carries the
    /// bcrypt hash the presented password is verified against. Credentials
    /// are read from the `Authorization` header only — never query or
    /// cookie carriers, which would leak passwords into logs.
    BasicAuth {
        /// Realm advertised in the `WWW-Authenticate: Basic realm="…"`
        /// challenge on 401 responses. Defaults to
        /// [`DEFAULT_BASIC_AUTH_REALM`].
        #[serde(default = "default_basic_auth_realm")]
        realm: String,
    },
}

impl Default for AuthConfig {
    /// Token auth against the `Authorization` header (protected by default).
    fn default() -> Self {
        Self::AuthToken {
            header: default_auth_header(),
            query_param: None,
            cookie: None,
        }
    }
}

impl AuthConfig {
    /// The mode's serialized tag (`"keyless"`, `"auth_token"`, …) — for
    /// logs and status/dashboard APIs.
    #[must_use]
    pub fn mode_name(&self) -> &'static str {
        match self {
            Self::Keyless => "keyless",
            Self::AuthToken { .. } => "auth_token",
            Self::Jwt { .. } => "jwt",
            Self::BasicAuth { .. } => "basic_auth",
        }
    }

    /// Validates auth settings; `api` names the owning definition in errors.
    fn validate(&self, api: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        match self {
            Self::Keyless => Ok(()),
            Self::AuthToken {
                header,
                query_param,
                cookie,
            } => {
                if http::header::HeaderName::from_bytes(header.as_bytes()).is_err() {
                    return Err(fail(format!(
                        "`auth.header` is not a valid header name: `{header}`"
                    )));
                }
                if query_param.as_deref().is_some_and(|p| p.trim().is_empty()) {
                    return Err(fail("`auth.query_param` must not be empty".into()));
                }
                if cookie.as_deref().is_some_and(|c| c.trim().is_empty()) {
                    return Err(fail("`auth.cookie` must not be empty".into()));
                }
                Ok(())
            }
            Self::Jwt {
                signing_method,
                secret,
                public_key_pem,
                header,
                identity_claim,
            } => {
                if http::header::HeaderName::from_bytes(header.as_bytes()).is_err() {
                    return Err(fail(format!(
                        "`auth.header` is not a valid header name: `{header}`"
                    )));
                }
                if identity_claim.trim().is_empty() {
                    return Err(fail("`auth.identity_claim` must not be empty".into()));
                }
                // Exactly the key material matching the algorithm must be
                // present; a mismatched field is a config typo worth failing.
                match signing_method {
                    JwtSigningMethod::Hs256 => {
                        if secret.as_deref().is_none_or(|s| s.trim().is_empty()) {
                            return Err(fail("hs256 requires a non-empty `auth.secret`".into()));
                        }
                        if public_key_pem.is_some() {
                            return Err(fail(
                                "`auth.public_key_pem` is not used with hs256; remove it".into(),
                            ));
                        }
                    }
                    JwtSigningMethod::Rs256 => {
                        if public_key_pem
                            .as_deref()
                            .is_none_or(|s| s.trim().is_empty())
                        {
                            return Err(fail(
                                "rs256 requires a non-empty `auth.public_key_pem`".into(),
                            ));
                        }
                        if secret.is_some() {
                            return Err(fail(
                                "`auth.secret` is not used with rs256; remove it".into(),
                            ));
                        }
                    }
                }
                Ok(())
            }
            Self::BasicAuth { realm } => {
                if realm.trim().is_empty() {
                    return Err(fail("`auth.realm` must not be empty".into()));
                }
                // The realm is embedded verbatim in a quoted-string header
                // value; restrict it to visible ASCII (plus space) without
                // `"` or `\` so the challenge is always a valid header.
                if !realm
                    .chars()
                    .all(|c| matches!(c, ' '..='~') && c != '"' && c != '\\')
                {
                    return Err(fail(
                        "`auth.realm` must be printable ASCII without `\"` or `\\`".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// One API proxied by the gateway.
///
/// This is the unit of configuration: requests whose path falls under
/// `listen_path` are forwarded to `target_url`.
///
/// Definitions come from two sources merged at load time (ADR-0002): files
/// (see [`crate::loader`]) and storage records under
/// [`api_definition_storage_key`], managed through the admin API.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "api_id": "httpbin",
///   "name": "Httpbin passthrough",
///   "listen_path": "/httpbin/",
///   "target_url": "http://httpbin.default.svc.cluster.local"
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiDefinition {
    /// Unique, stable identifier for this API.
    pub api_id: String,

    /// Human-readable name (shown in logs and the future dashboard).
    pub name: String,

    /// Owning organization. Always [`DEFAULT_ORG_ID`] in single-org mode.
    #[serde(default = "default_org_id")]
    pub org_id: String,

    /// URL path prefix the gateway listens on for this API. Must begin with `/`.
    pub listen_path: String,

    /// Base URL of the upstream service, e.g. `http://users.svc:8000/api`.
    /// Must be an absolute `http`/`https` URL.
    pub target_url: String,

    /// When `true` (the default), the `listen_path` prefix is removed from the
    /// request path before the request is forwarded upstream.
    #[serde(default = "default_true")]
    pub strip_listen_path: bool,

    /// When `true`, the client's original `Host` header is forwarded upstream.
    /// When `false` (the default), the upstream host from `target_url` is used.
    #[serde(default)]
    pub preserve_host_header: bool,

    /// Maximum time in milliseconds to wait for the upstream response before
    /// answering `504 Gateway Timeout`.
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,

    /// Inactive definitions are loaded and listed but never routed to.
    #[serde(default = "default_true")]
    pub active: bool,

    /// How clients authenticate. Defaults to token auth on the
    /// `Authorization` header; keyless must be requested explicitly.
    #[serde(default)]
    pub auth: AuthConfig,

    /// Optional header add/remove transforms applied to this API's
    /// upstream-bound requests and client-bound responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform_headers: Option<HeaderTransforms>,

    /// Regex URL rewrite rules, tried in order against the full client
    /// request path; the first match decides the upstream path (see
    /// [`UrlRewriteRule`]). Requests matching no rule follow the normal
    /// listen-path strip/join.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_rewrites: Vec<UrlRewriteRule>,

    /// Optional HTTP method override for upstream-bound requests (e.g.
    /// `"POST"`, case-insensitive; `CONNECT` is not allowed). The body and
    /// headers are forwarded unchanged, and gateway responses still describe
    /// the client's original method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform_method: Option<String>,

    /// When non-empty, only requests matching one of these rules are
    /// forwarded; everything else on this API is rejected with `403` (the
    /// API becomes allow-list-only). See [`crate::endpoints`] for the
    /// evaluation order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_paths: Vec<PathRule>,

    /// Requests matching one of these rules are rejected with `403`. A
    /// block always wins: it applies even to paths that are also allowed,
    /// ignored, or mocked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_paths: Vec<PathRule>,

    /// Requests matching one of these rules skip authentication (and with
    /// it rate limiting, which needs a session) — e.g. a public health or
    /// webhook endpoint on an otherwise protected API.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_auth_paths: Vec<PathRule>,

    /// Mock-response rules, tried in order after auth and rate limiting;
    /// the first match is answered by the gateway without contacting the
    /// upstream (see [`MockResponse`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mock_responses: Vec<MockResponse>,
}

/// Storage key holding one API definition: `g2:{org_id}:apidef:{api_id}`.
///
/// Definitions are persisted as JSON-encoded [`ApiDefinition`] records under
/// this key (see ADR-0002); the set of definitions in an organization is
/// enumerated by scanning [`api_definition_key_prefix`].
#[must_use]
pub fn api_definition_storage_key(org_id: &str, api_id: &str) -> String {
    format!("{}{api_id}", api_definition_key_prefix(org_id))
}

/// Prefix shared by every API definition key in `org_id`: `g2:{org_id}:apidef:`.
#[must_use]
pub fn api_definition_key_prefix(org_id: &str) -> String {
    format!("g2:{org_id}:apidef:")
}

impl ApiDefinition {
    /// Validates the semantic invariants that serde cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a field is empty, the
    /// listen path does not start with `/`, the target URL is not an absolute
    /// `http`/`https` URL, or the timeout is zero.
    pub fn validate(&self) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: self.api_id.clone(),
            reason,
        };

        if self.api_id.trim().is_empty() {
            return Err(fail("`api_id` must not be empty".into()));
        }
        if self.name.trim().is_empty() {
            return Err(fail("`name` must not be empty".into()));
        }
        if self.org_id.trim().is_empty() {
            return Err(fail("`org_id` must not be empty".into()));
        }
        if !self.listen_path.starts_with('/') {
            return Err(fail(format!(
                "`listen_path` must start with '/', got `{}`",
                self.listen_path
            )));
        }
        if self.upstream_timeout_ms == 0 {
            return Err(fail(
                "`upstream_timeout_ms` must be greater than zero".into(),
            ));
        }

        let uri: Uri = self
            .target_url
            .parse()
            .map_err(|e| fail(format!("`target_url` is not a valid URL: {e}")))?;
        match uri.scheme_str() {
            Some("http") | Some("https") => {}
            other => {
                return Err(fail(format!(
                    "`target_url` must use http or https, got `{}`",
                    other.unwrap_or("<none>")
                )));
            }
        }
        if uri.authority().is_none() {
            return Err(fail("`target_url` must include a host".into()));
        }
        self.auth.validate(&self.api_id)?;
        if let Some(transforms) = &self.transform_headers {
            transforms.validate(&self.api_id)?;
        }
        for (index, rule) in self.url_rewrites.iter().enumerate() {
            rule.validate(&self.api_id, index)?;
        }
        if let Some(method) = &self.transform_method {
            transform::validate_transform_method(method, &self.api_id)?;
        }
        for (list, rules) in [
            ("allow_paths", &self.allow_paths),
            ("block_paths", &self.block_paths),
            ("ignore_auth_paths", &self.ignore_auth_paths),
        ] {
            for (index, rule) in rules.iter().enumerate() {
                rule.validate(&self.api_id, list, index)?;
            }
        }
        for (index, mock) in self.mock_responses.iter().enumerate() {
            mock.validate(&self.api_id, index)?;
        }
        Ok(())
    }

    /// The parsed [`Uri`] form of [`Self::target_url`].
    ///
    /// # Panics
    ///
    /// Panics if the definition has not passed [`Self::validate`]; callers
    /// must validate before routing.
    #[must_use]
    pub fn target_uri(&self) -> Uri {
        self.target_url
            .parse()
            .expect("target_url validated as a URI")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_json() -> &'static str {
        r#"{
            "api_id": "users",
            "name": "Users API",
            "listen_path": "/users/",
            "target_url": "http://users.internal:8000"
        }"#
    }

    fn parse(json: &str) -> ApiDefinition {
        serde_json::from_str(json).expect("valid definition JSON")
    }

    #[test]
    fn minimal_definition_gets_defaults() {
        let def = parse(minimal_json());
        assert_eq!(def.org_id, DEFAULT_ORG_ID);
        assert!(def.strip_listen_path);
        assert!(!def.preserve_host_header);
        assert!(def.active);
        assert_eq!(def.upstream_timeout_ms, 30_000);
        def.validate().expect("minimal definition is valid");
    }

    #[test]
    fn listen_path_must_start_with_slash() {
        let mut def = parse(minimal_json());
        def.listen_path = "users/".into();
        let err = def.validate().unwrap_err();
        assert!(err.to_string().contains("listen_path"), "got: {err}");
    }

    #[test]
    fn target_url_must_be_absolute_http() {
        let mut def = parse(minimal_json());
        for bad in ["/relative/path", "ftp://x.example", "users.internal:8000"] {
            def.target_url = bad.into();
            assert!(def.validate().is_err(), "expected `{bad}` to be rejected");
        }
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let mut def = parse(minimal_json());
        def.upstream_timeout_ms = 0;
        assert!(def.validate().is_err());
    }

    #[test]
    fn empty_fields_are_rejected() {
        for field in ["api_id", "name"] {
            let mut def = parse(minimal_json());
            match field {
                "api_id" => def.api_id = "  ".into(),
                _ => def.name = String::new(),
            }
            assert!(def.validate().is_err(), "expected empty `{field}` rejected");
        }
    }

    #[test]
    fn auth_defaults_to_token_on_authorization_header() {
        let def = parse(minimal_json());
        assert_eq!(def.auth, AuthConfig::default());
        match &def.auth {
            AuthConfig::AuthToken {
                header,
                query_param,
                cookie,
            } => {
                assert_eq!(header, DEFAULT_AUTH_HEADER);
                assert!(query_param.is_none() && cookie.is_none());
            }
            other => panic!("default must be auth_token, got {other:?}"),
        }
    }

    #[test]
    fn keyless_must_be_explicit() {
        let json = r#"{
            "api_id": "open",
            "name": "Open API",
            "listen_path": "/open/",
            "target_url": "http://open.internal",
            "auth": { "mode": "keyless" }
        }"#;
        let def = parse(json);
        assert_eq!(def.auth, AuthConfig::Keyless);
        def.validate().expect("keyless definition is valid");
    }

    #[test]
    fn auth_token_carriers_are_configurable() {
        let json = r#"{
            "api_id": "custom",
            "name": "Custom",
            "listen_path": "/c/",
            "target_url": "http://c.internal",
            "auth": { "mode": "auth_token", "header": "X-Api-Key", "query_param": "api_key" }
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        assert_eq!(
            def.auth,
            AuthConfig::AuthToken {
                header: "X-Api-Key".into(),
                query_param: Some("api_key".into()),
                cookie: None,
            }
        );
    }

    #[test]
    fn invalid_auth_settings_are_rejected() {
        let mut def = parse(minimal_json());
        def.auth = AuthConfig::AuthToken {
            header: "bad header\n".into(),
            query_param: None,
            cookie: None,
        };
        assert!(def.validate().is_err());

        def.auth = AuthConfig::AuthToken {
            header: DEFAULT_AUTH_HEADER.into(),
            query_param: Some("  ".into()),
            cookie: None,
        };
        assert!(def.validate().is_err());
    }

    #[test]
    fn jwt_auth_validates_key_material_per_algorithm() {
        let mut def = parse(minimal_json());

        // hs256 with a secret: valid.
        def.auth = AuthConfig::Jwt {
            signing_method: JwtSigningMethod::Hs256,
            secret: Some("shhh".into()),
            public_key_pem: None,
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        def.validate().expect("hs256 with secret is valid");

        // hs256 without a secret / with a stray PEM: invalid.
        def.auth = AuthConfig::Jwt {
            signing_method: JwtSigningMethod::Hs256,
            secret: None,
            public_key_pem: None,
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        assert!(def.validate().is_err());
        def.auth = AuthConfig::Jwt {
            signing_method: JwtSigningMethod::Hs256,
            secret: Some("shhh".into()),
            public_key_pem: Some("-----BEGIN PUBLIC KEY-----".into()),
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        assert!(def.validate().is_err());

        // rs256 requires a PEM and no secret.
        def.auth = AuthConfig::Jwt {
            signing_method: JwtSigningMethod::Rs256,
            secret: None,
            public_key_pem: Some("-----BEGIN PUBLIC KEY-----".into()),
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        def.validate().expect("rs256 with pem is valid");
        def.auth = AuthConfig::Jwt {
            signing_method: JwtSigningMethod::Rs256,
            secret: Some("shhh".into()),
            public_key_pem: Some("-----BEGIN PUBLIC KEY-----".into()),
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        assert!(def.validate().is_err());
    }

    #[test]
    fn jwt_json_defaults_header_and_identity_claim() {
        let json = r#"{
            "api_id": "j",
            "name": "j",
            "listen_path": "/j/",
            "target_url": "http://j.internal",
            "auth": { "mode": "jwt", "signing_method": "hs256", "secret": "shhh" }
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        match def.auth {
            AuthConfig::Jwt {
                header,
                identity_claim,
                ..
            } => {
                assert_eq!(header, DEFAULT_AUTH_HEADER);
                assert_eq!(identity_claim, DEFAULT_IDENTITY_CLAIM);
            }
            other => panic!("expected jwt auth, got {other:?}"),
        }
    }

    #[test]
    fn basic_auth_json_defaults_realm() {
        let json = r#"{
            "api_id": "b",
            "name": "b",
            "listen_path": "/b/",
            "target_url": "http://b.internal",
            "auth": { "mode": "basic_auth" }
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        assert_eq!(
            def.auth,
            AuthConfig::BasicAuth {
                realm: DEFAULT_BASIC_AUTH_REALM.into()
            }
        );
    }

    #[test]
    fn basic_auth_explicit_realm_round_trips() {
        let mut def = parse(minimal_json());
        def.auth = AuthConfig::BasicAuth {
            realm: "internal apis".into(),
        };
        def.validate().expect("valid");
        let json = serde_json::to_string(&def).expect("serializes");
        let back: ApiDefinition = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back.auth, def.auth);
    }

    #[test]
    fn basic_auth_invalid_realms_are_rejected() {
        let mut def = parse(minimal_json());
        for bad in ["", "  ", "with \"quotes\"", "back\\slash", "ctrl\nchar"] {
            def.auth = AuthConfig::BasicAuth { realm: bad.into() };
            assert!(def.validate().is_err(), "expected realm `{bad:?}` rejected");
        }
    }

    #[test]
    fn url_rewrites_and_transform_method_parse_and_validate() {
        let json = r#"{
            "api_id": "u",
            "name": "u",
            "listen_path": "/u/",
            "target_url": "http://u.internal",
            "url_rewrites": [
                {"pattern": "^/u/(\\d+)$", "rewrite": "/people/$1"}
            ],
            "transform_method": "POST"
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        assert_eq!(def.url_rewrites.len(), 1);
        assert_eq!(def.transform_method.as_deref(), Some("POST"));

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        assert!(!bare.contains("url_rewrites") && !bare.contains("transform_method"));
    }

    #[test]
    fn invalid_url_rewrites_and_methods_are_rejected() {
        let mut def = parse(minimal_json());
        def.url_rewrites = vec![super::UrlRewriteRule {
            pattern: "(".into(),
            rewrite: "/x".into(),
        }];
        assert!(def.validate().is_err());

        let mut def = parse(minimal_json());
        def.transform_method = Some("CONNECT".into());
        assert!(def.validate().is_err());
    }

    #[test]
    fn path_lists_and_mocks_parse_and_validate() {
        let json = r#"{
            "api_id": "p",
            "name": "p",
            "listen_path": "/p/",
            "target_url": "http://p.internal",
            "allow_paths": [{"pattern": "^/p/public/"}],
            "block_paths": [{"pattern": "^/p/public/admin$", "methods": ["POST"]}],
            "ignore_auth_paths": [{"pattern": "^/p/public/ping$"}],
            "mock_responses": [
                {"pattern": "^/p/public/ping$", "status": 200, "body": "pong"}
            ]
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        assert_eq!(def.allow_paths.len(), 1);
        assert_eq!(def.block_paths[0].methods, vec!["POST"]);
        assert_eq!(def.mock_responses[0].body, "pong");

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        for field in [
            "allow_paths",
            "block_paths",
            "ignore_auth_paths",
            "mock_responses",
        ] {
            assert!(!bare.contains(field), "`{field}` serialized when empty");
        }

        // A broken rule in any list fails validation, naming the list.
        let mut def = parse(minimal_json());
        def.block_paths = vec![super::PathRule {
            pattern: "(".into(),
            methods: vec![],
        }];
        let err = def.validate().unwrap_err().to_string();
        assert!(err.contains("block_paths[0]"), "got: {err}");

        let mut def = parse(minimal_json());
        def.mock_responses = vec![super::MockResponse {
            pattern: "^/x$".into(),
            methods: vec![],
            status: 42,
            body: String::new(),
            headers: Default::default(),
        }];
        assert!(def.validate().is_err());
    }

    #[test]
    fn storage_key_follows_schema() {
        assert_eq!(
            api_definition_storage_key("default", "httpbin"),
            "g2:default:apidef:httpbin"
        );
        assert_eq!(api_definition_key_prefix("default"), "g2:default:apidef:");
    }

    #[test]
    fn target_uri_round_trips() {
        let def = parse(minimal_json());
        let uri = def.target_uri();
        assert_eq!(uri.host(), Some("users.internal"));
        assert_eq!(uri.port_u16(), Some(8000));
    }
}
