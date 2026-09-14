//! Endpoint-level traffic rules (milestone M6): allow/block/ignore path
//! lists, mock responses and per-endpoint rate limits for one API.
//!
//! Like [`transform`](crate::transform), this module is pure configuration —
//! parsing and validation. The runtime enforcement lives in `g2-middleware`
//! (`PathPolicyLayer`, `MockResponseLayer` and the endpoint half of
//! `RateLimitLayer`), precompiled at route-build time so the hot path runs
//! no regex compilation (ADR-0001).
//!
//! # Semantics
//!
//! All patterns are regexes searched (unanchored — anchor with `^`/`$` as
//! needed) against the **full client request path**, listen path included,
//! matching [`UrlRewriteRule`](crate::UrlRewriteRule). A rule with an empty
//! `methods` list applies to every method.
//!
//! Evaluation order per request, deliberately **strict** (an ignored path
//! does not bypass the block list):
//!
//! 1. `block_paths` — a match is rejected with `403`, unconditionally.
//! 2. `allow_paths` — when non-empty, a request matching no rule is
//!    rejected with `403` (the API becomes allow-list-only).
//! 3. `ignore_auth_paths` — a match skips authentication (and therefore
//!    session rate limiting, which needs a session) for this request only.
//!    API-level `endpoint_rate_limits` still apply: they count aggregate
//!    traffic, no session needed.
//! 4. `mock_responses` — evaluated after auth/rate limiting: mocks on a
//!    protected API require credentials unless the path is also ignored.
//!
//! `endpoint_rate_limits` are evaluated before any session limit (first
//! matching rule wins); see [`EndpointRateLimit`].

use std::collections::BTreeMap;

use http::header::{HeaderName, HeaderValue};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::session::RateLimit;
use crate::transform::{HOP_BY_HOP, TRANSFORM_METHODS};
use crate::Error;

/// One path-matching rule in an allow/block/ignore list.
///
/// # Example (JSON)
///
/// ```json
/// { "pattern": "^/users/internal/", "methods": ["POST", "DELETE"] }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRule {
    /// Regex searched against the full client request path.
    pub pattern: String,

    /// Methods the rule applies to (case-insensitive). Empty = every method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
}

impl PathRule {
    /// Validates one rule; `api` names the owning definition, `list` the
    /// owning field and `index` the rule's position in errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the pattern is not a
    /// valid regex or a method is not a standard HTTP method.
    pub fn validate(&self, api: &str, list: &str, index: usize) -> Result<(), Error> {
        validate_pattern(&self.pattern, api, list, index)?;
        validate_methods(&self.methods, api, list, index)
    }
}

fn default_mock_status() -> u16 {
    200
}

/// One mock-response rule: requests matching it are answered by the gateway
/// itself, without contacting the upstream.
///
/// Rules are tried in order; the first match wins. The response carries
/// exactly the configured `status`, `headers` and `body` — no content type
/// is implied, set one in `headers` when the body needs it.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "pattern": "^/users/ping$",
///   "methods": ["GET"],
///   "status": 200,
///   "body": "{\"pong\":true}",
///   "headers": { "Content-Type": "application/json" }
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockResponse {
    /// Regex searched against the full client request path.
    pub pattern: String,

    /// Methods the rule applies to (case-insensitive). Empty = every method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,

    /// HTTP status of the mock response. Defaults to `200`.
    #[serde(default = "default_mock_status")]
    pub status: u16,

    /// Literal response body. Defaults to empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,

    /// Response headers: name → literal value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

impl MockResponse {
    /// Validates one rule; `api` names the owning definition and `index`
    /// the rule's position in errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the pattern is not a
    /// valid regex, a method is not a standard HTTP method, the status is
    /// not a valid HTTP status code, a header name/value does not parse, or
    /// a header is hop-by-hop.
    pub fn validate(&self, api: &str, index: usize) -> Result<(), Error> {
        const LIST: &str = "mock_responses";
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        validate_pattern(&self.pattern, api, LIST, index)?;
        validate_methods(&self.methods, api, LIST, index)?;
        if StatusCode::from_u16(self.status).is_err() || self.status > 599 {
            return Err(fail(format!(
                "`{LIST}[{index}].status` is not a valid HTTP status code: {}",
                self.status
            )));
        }
        for (name, value) in &self.headers {
            if HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(fail(format!(
                    "`{LIST}[{index}].headers` name is not a valid header name: `{name}`"
                )));
            }
            if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                return Err(fail(format!(
                    "`{LIST}[{index}].headers` must not set hop-by-hop header `{name}`"
                )));
            }
            if HeaderValue::from_str(value).is_err() {
                return Err(fail(format!(
                    "`{LIST}[{index}].headers` value for `{name}` is not a valid header value"
                )));
            }
        }
        Ok(())
    }
}

/// One API-level endpoint rate limit: the first rule matching a request caps
/// how many matching requests **all clients combined** may make per window.
///
/// Counters are aggregate — they are not tied to any key session, so the
/// limit also protects keyless APIs and `ignore_auth_paths` matches. Excess
/// requests are rejected with `429` and the usual `X-RateLimit-*` headers.
/// Rules are tried in order; only the first match is checked and consumed.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "pattern": "^/users/search",
///   "methods": ["POST"],
///   "rate": { "requests": 10, "per_seconds": 60 }
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRateLimit {
    /// Regex searched against the full client request path.
    pub pattern: String,

    /// Methods the rule applies to (case-insensitive). Empty = every method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,

    /// The aggregate allowance for matching requests, across all clients.
    pub rate: RateLimit,
}

impl EndpointRateLimit {
    /// Validates one rule; `api` names the owning definition and `index`
    /// the rule's position in errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the pattern is not a
    /// valid regex, a method is not a standard HTTP method, or the rate's
    /// `requests`/`per_seconds` is zero (omit the rule for unlimited — a
    /// zero limit would silently deny everything).
    pub fn validate(&self, api: &str, index: usize) -> Result<(), Error> {
        const LIST: &str = "endpoint_rate_limits";
        validate_pattern(&self.pattern, api, LIST, index)?;
        validate_methods(&self.methods, api, LIST, index)?;
        for (field, value) in [
            ("requests", self.rate.requests),
            ("per_seconds", self.rate.per_seconds),
        ] {
            if value == 0 {
                return Err(Error::InvalidApiDefinition {
                    api: api.to_owned(),
                    reason: format!(
                        "`{LIST}[{index}].rate.{field}` must be greater than zero \
                         (omit the rule for unlimited)"
                    ),
                });
            }
        }
        Ok(())
    }
}

/// Builds the storage key for one endpoint rule's aggregate sliding-window
/// counter: `g2:{org_id}:endpointrl:{scope}:{index}`. `scope` is the API id,
/// or `{api_id}:{version}` for one version of a versioned API — versions can
/// declare different limits, so they never share counters.
#[must_use]
pub fn endpoint_rate_limit_storage_key(org_id: &str, scope: &str, index: usize) -> String {
    format!("g2:{org_id}:endpointrl:{scope}:{index}")
}

fn validate_pattern(pattern: &str, api: &str, list: &str, index: usize) -> Result<(), Error> {
    regex::Regex::new(pattern)
        .map(|_| ())
        .map_err(|err| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason: format!("`{list}[{index}].pattern` is not a valid regex: {err}"),
        })
}

fn validate_methods(methods: &[String], api: &str, list: &str, index: usize) -> Result<(), Error> {
    for method in methods {
        if !TRANSFORM_METHODS
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
        {
            return Err(Error::InvalidApiDefinition {
                api: api.to_owned(),
                reason: format!(
                    "`{list}[{index}].methods` must contain only standard HTTP methods \
                     ({}), got `{method}`",
                    TRANSFORM_METHODS.join(", ")
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path_rule(pattern: &str, methods: &[&str]) -> PathRule {
        PathRule {
            pattern: pattern.into(),
            methods: methods.iter().map(|m| (*m).to_owned()).collect(),
        }
    }

    #[test]
    fn path_rules_validate() {
        path_rule("^/x$", &[])
            .validate("api", "block_paths", 0)
            .expect("valid");
        path_rule("^/x$", &["get", "POST"])
            .validate("api", "block_paths", 0)
            .expect("methods are case-insensitive");

        let err = path_rule("(", &[])
            .validate("api", "allow_paths", 2)
            .unwrap_err()
            .to_string();
        assert!(err.contains("allow_paths[2].pattern"), "got: {err}");

        let err = path_rule("^/x$", &["FETCH"])
            .validate("api", "ignore_auth_paths", 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ignore_auth_paths[0].methods"), "got: {err}");
    }

    #[test]
    fn path_rule_round_trips_and_omits_empty_methods() {
        let rule: PathRule = serde_json::from_str(r#"{"pattern": "^/a$"}"#).expect("parses");
        assert!(rule.methods.is_empty());
        let json = serde_json::to_string(&rule).expect("serializes");
        assert!(!json.contains("methods"));
        assert_eq!(serde_json::from_str::<PathRule>(&json).expect("back"), rule);
    }

    #[test]
    fn mock_response_defaults_and_round_trip() {
        let mock: MockResponse = serde_json::from_str(r#"{"pattern": "^/ping$"}"#).expect("parses");
        assert_eq!(mock.status, 200);
        assert!(mock.body.is_empty() && mock.headers.is_empty());
        mock.validate("api", 0).expect("valid");

        let full: MockResponse = serde_json::from_str(
            r#"{
                "pattern": "^/ping$",
                "methods": ["GET"],
                "status": 418,
                "body": "teapot",
                "headers": {"Content-Type": "text/plain"}
            }"#,
        )
        .expect("parses");
        full.validate("api", 0).expect("valid");
        let json = serde_json::to_string(&full).expect("serializes");
        assert_eq!(
            serde_json::from_str::<MockResponse>(&json).expect("back"),
            full
        );
    }

    #[test]
    fn mock_response_invalid_configs_are_rejected() {
        let base = || MockResponse {
            pattern: "^/x$".into(),
            methods: vec![],
            status: 200,
            body: String::new(),
            headers: BTreeMap::new(),
        };

        let mut m = base();
        m.pattern = "(".into();
        assert!(m.validate("api", 0).is_err(), "bad regex");

        let mut m = base();
        m.status = 99;
        assert!(m.validate("api", 0).is_err(), "status below 100");
        m.status = 600;
        assert!(m.validate("api", 0).is_err(), "status above 599");

        let mut m = base();
        m.headers.insert("bad name\n".into(), "v".into());
        assert!(m.validate("api", 0).is_err(), "bad header name");

        let mut m = base();
        m.headers.insert("X-A".into(), "line\nbreak".into());
        assert!(m.validate("api", 0).is_err(), "bad header value");

        let mut m = base();
        m.headers
            .insert("Transfer-Encoding".into(), "chunked".into());
        assert!(m.validate("api", 0).is_err(), "hop-by-hop header");

        let mut m = base();
        m.methods = vec!["CONNECT".into()];
        assert!(m.validate("api", 0).is_err(), "non-standard method");
    }

    fn endpoint_limit(pattern: &str, requests: u64, per_seconds: u64) -> EndpointRateLimit {
        EndpointRateLimit {
            pattern: pattern.into(),
            methods: vec![],
            rate: RateLimit {
                requests,
                per_seconds,
            },
        }
    }

    #[test]
    fn endpoint_rate_limits_validate() {
        endpoint_limit("^/x$", 10, 60)
            .validate("api", 0)
            .expect("valid");

        let err = endpoint_limit("(", 10, 60)
            .validate("api", 1)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("endpoint_rate_limits[1].pattern"),
            "got: {err}"
        );

        let mut rule = endpoint_limit("^/x$", 10, 60);
        rule.methods = vec!["FETCH".into()];
        let err = rule.validate("api", 0).unwrap_err().to_string();
        assert!(
            err.contains("endpoint_rate_limits[0].methods"),
            "got: {err}"
        );

        let err = endpoint_limit("^/x$", 0, 60)
            .validate("api", 2)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("endpoint_rate_limits[2].rate.requests"),
            "got: {err}"
        );

        let err = endpoint_limit("^/x$", 10, 0)
            .validate("api", 0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("endpoint_rate_limits[0].rate.per_seconds"),
            "got: {err}"
        );
    }

    #[test]
    fn endpoint_rate_limit_round_trips_and_omits_empty_methods() {
        let rule: EndpointRateLimit = serde_json::from_str(
            r#"{"pattern": "^/a$", "rate": {"requests": 5, "per_seconds": 30}}"#,
        )
        .expect("parses");
        assert!(rule.methods.is_empty());
        assert_eq!(rule.rate.requests, 5);
        let json = serde_json::to_string(&rule).expect("serializes");
        assert!(!json.contains("methods"));
        assert_eq!(
            serde_json::from_str::<EndpointRateLimit>(&json).expect("back"),
            rule
        );
    }

    #[test]
    fn endpoint_rate_limit_storage_key_shape() {
        assert_eq!(
            endpoint_rate_limit_storage_key("default", "users-api", 3),
            "g2:default:endpointrl:users-api:3"
        );
        assert_eq!(
            endpoint_rate_limit_storage_key("acme", "users-api:v2", 0),
            "g2:acme:endpointrl:users-api:v2:0"
        );
    }
}
