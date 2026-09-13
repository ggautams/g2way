//! Traffic-transform configuration (milestone M6): header add/remove rules,
//! regex URL rewrites, and method transforms applied to one API's traffic.
//!
//! The model here is pure configuration — parsing and validation. The
//! runtime application lives elsewhere, precompiled at route-build time so
//! the hot path does no parsing (ADR-0001): header transforms in
//! `g2-middleware` (`HeaderTransformLayer`), URL rewrites and method
//! transforms in `g2-proxy`'s forwarder, where the upstream URL is built.

use std::collections::BTreeMap;

use http::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::Error;

/// Hop-by-hop headers (RFC 9110 §7.6.1). They describe one connection, not
/// the message, so `add`ing them through a transform is a configuration
/// error: on the request side the forwarder strips them anyway, and on the
/// response side they could corrupt the client connection.
pub(crate) const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Header add/remove rules for one direction (request or response).
///
/// `remove` runs before `add`, and `add` replaces any existing value — so a
/// name appearing in both ends up set to the `add` value, and adding an
/// already-present header overwrites it rather than appending.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderTransform {
    /// Headers to set on the message: name → literal value. An existing
    /// header of the same name is replaced.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub add: BTreeMap<String, String>,

    /// Header names to remove from the message (applied before `add`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}

impl HeaderTransform {
    /// Whether this direction has no rules at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }

    fn validate(&self, api: &str, direction: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        for (name, value) in &self.add {
            if HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(fail(format!(
                    "`transform_headers.{direction}.add` name is not a valid header name: `{name}`"
                )));
            }
            if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                return Err(fail(format!(
                    "`transform_headers.{direction}.add` must not set hop-by-hop header `{name}`"
                )));
            }
            if HeaderValue::from_str(value).is_err() {
                return Err(fail(format!(
                    "`transform_headers.{direction}.add` value for `{name}` is not a valid \
                     header value"
                )));
            }
        }
        for name in &self.remove {
            if HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(fail(format!(
                    "`transform_headers.{direction}.remove` entry is not a valid header name: \
                     `{name}`"
                )));
            }
        }
        Ok(())
    }
}

/// Request and response header transforms for one API.
///
/// Configured on an [`ApiDefinition`](crate::ApiDefinition) as
/// `transform_headers`; applied only to traffic that reaches the forwarding
/// stage (gateway-generated auth/rate-limit rejections are not
/// transformed).
///
/// # Example (JSON)
///
/// ```json
/// {
///   "request": {
///     "add": { "X-Env": "prod" },
///     "remove": ["X-Internal-Debug"]
///   },
///   "response": {
///     "add": { "X-Gateway": "g2way" },
///     "remove": ["Server"]
///   }
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderTransforms {
    /// Rules applied to the upstream-bound request.
    #[serde(default, skip_serializing_if = "HeaderTransform::is_empty")]
    pub request: HeaderTransform,

    /// Rules applied to the client-bound response.
    #[serde(default, skip_serializing_if = "HeaderTransform::is_empty")]
    pub response: HeaderTransform,
}

impl HeaderTransforms {
    /// Whether neither direction has any rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.request.is_empty() && self.response.is_empty()
    }

    /// Validates every rule; `api` names the owning definition in errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a header name is not a
    /// valid HTTP header name, a value is not a valid header value, or an
    /// `add` names a hop-by-hop header.
    pub fn validate(&self, api: &str) -> Result<(), Error> {
        self.request.validate(api, "request")?;
        self.response.validate(api, "response")
    }
}

/// One regex URL rewrite rule for an API.
///
/// Rules live on an [`ApiDefinition`](crate::ApiDefinition) as
/// `url_rewrites` and are tried in order; the first whose `pattern` matches
/// wins, and a request matching no rule is forwarded with the normal
/// listen-path strip/join.
///
/// - `pattern` is a regex searched (unanchored — anchor with `^`/`$` as
///   needed) against the **full client request path**, listen path
///   included, before any stripping.
/// - `rewrite` is the replacement template producing the upstream path:
///   `$1`/`${name}` expand capture groups (`$$` is a literal `$`; a group
///   that did not participate expands to the empty string). It must start
///   with `/` and replaces the listen-path strip — the result is joined
///   onto the target URL's base path exactly like a stripped tail. It may
///   carry its own query string (`/new?flag=1`); the client's query is
///   appended after it.
///
/// # Example (JSON)
///
/// ```json
/// { "pattern": "^/users/(\\d+)/profile$", "rewrite": "/profiles/$1" }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlRewriteRule {
    /// Regex searched against the full client request path.
    pub pattern: String,

    /// Replacement template for the upstream path (must start with `/`).
    pub rewrite: String,
}

impl UrlRewriteRule {
    /// Validates one rule; `api` names the owning definition and `index`
    /// the rule's position in errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the pattern is not a
    /// valid regex or the rewrite does not start with `/`.
    pub fn validate(&self, api: &str, index: usize) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        if let Err(err) = regex::Regex::new(&self.pattern) {
            return Err(fail(format!(
                "`url_rewrites[{index}].pattern` is not a valid regex: {err}"
            )));
        }
        if !self.rewrite.starts_with('/') {
            return Err(fail(format!(
                "`url_rewrites[{index}].rewrite` must start with '/', got `{}`",
                self.rewrite
            )));
        }
        Ok(())
    }
}

/// Methods a `transform_method` may rewrite an upstream request to: the
/// RFC 9110 set minus `CONNECT`, which addresses the proxy itself and can
/// never be a sensible upstream verb.
pub(crate) const TRANSFORM_METHODS: [&str; 8] = [
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
];

/// Validates an [`ApiDefinition`](crate::ApiDefinition) `transform_method`
/// value (case-insensitive); `api` names the owning definition in errors.
///
/// # Errors
///
/// Returns [`Error::InvalidApiDefinition`] when `method` is not one of the
/// standard HTTP methods (`CONNECT` excluded).
pub fn validate_transform_method(method: &str, api: &str) -> Result<(), Error> {
    if TRANSFORM_METHODS
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
    {
        Ok(())
    } else {
        Err(Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason: format!(
                "`transform_method` must be one of {} (got `{method}`)",
                TRANSFORM_METHODS.join(", ")
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> HeaderTransforms {
        serde_json::from_str(json).expect("valid transform JSON")
    }

    #[test]
    fn empty_and_partial_configs_parse() {
        assert!(parse("{}").is_empty());
        let t = parse(r#"{"request": {"add": {"X-Env": "prod"}}}"#);
        assert!(!t.is_empty());
        assert!(t.response.is_empty());
        assert_eq!(t.request.add["X-Env"], "prod");
        t.validate("api").expect("valid");
    }

    #[test]
    fn full_config_round_trips() {
        let t = parse(
            r#"{
                "request": {"add": {"X-A": "1"}, "remove": ["X-B"]},
                "response": {"add": {"X-C": "2"}, "remove": ["Server"]}
            }"#,
        );
        t.validate("api").expect("valid");
        let json = serde_json::to_string(&t).expect("serializes");
        assert_eq!(parse(&json), t);
    }

    #[test]
    fn invalid_header_names_are_rejected() {
        for json in [
            r#"{"request": {"add": {"bad name\n": "v"}}}"#,
            r#"{"response": {"remove": ["bad name\n"]}}"#,
            r#"{"request": {"add": {"": "v"}}}"#,
        ] {
            let t = parse(json);
            assert!(t.validate("api").is_err(), "expected `{json}` rejected");
        }
    }

    #[test]
    fn invalid_header_values_are_rejected() {
        let t = parse(r#"{"request": {"add": {"X-A": "line\nbreak"}}}"#);
        assert!(t.validate("api").is_err());
    }

    #[test]
    fn url_rewrite_rules_validate() {
        let rule = |pattern: &str, rewrite: &str| UrlRewriteRule {
            pattern: pattern.into(),
            rewrite: rewrite.into(),
        };
        rule(r"^/users/(\d+)$", "/people/$1")
            .validate("api", 0)
            .expect("valid rule");
        // A rewrite may carry its own query string.
        rule("^/a$", "/b?flag=1").validate("api", 0).expect("valid");

        let err = rule(r"^/users/(\d+$", "/x")
            .validate("api", 3)
            .unwrap_err()
            .to_string();
        assert!(err.contains("url_rewrites[3].pattern"), "got: {err}");

        let err = rule("^/a$", "no-slash").validate("api", 0).unwrap_err();
        assert!(err.to_string().contains("must start with '/'"));
    }

    #[test]
    fn url_rewrite_rule_round_trips() {
        let rule: UrlRewriteRule =
            serde_json::from_str(r#"{"pattern": "^/a/(.*)$", "rewrite": "/b/$1"}"#)
                .expect("parses");
        let json = serde_json::to_string(&rule).expect("serializes");
        assert_eq!(
            serde_json::from_str::<UrlRewriteRule>(&json).expect("back"),
            rule
        );
    }

    #[test]
    fn transform_methods_are_validated_case_insensitively() {
        for ok in ["GET", "post", "Delete", "OPTIONS"] {
            validate_transform_method(ok, "api").expect("allowed method");
        }
        for bad in ["CONNECT", "FETCH", "", "G ET"] {
            assert!(
                validate_transform_method(bad, "api").is_err(),
                "expected `{bad}` rejected"
            );
        }
    }

    #[test]
    fn hop_by_hop_adds_are_rejected_case_insensitively() {
        for name in ["Connection", "transfer-encoding", "Upgrade"] {
            let t = parse(&format!(r#"{{"response": {{"add": {{"{name}": "x"}}}}}}"#));
            assert!(t.validate("api").is_err(), "expected `{name}` rejected");
        }
        // Removing them is allowed (harmless / defensive).
        let t = parse(r#"{"response": {"remove": ["Connection"]}}"#);
        t.validate("api").expect("remove of hop-by-hop is fine");
    }
}
