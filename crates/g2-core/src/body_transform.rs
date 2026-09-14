//! Request/response body-transform configuration (milestone M8+): minijinja
//! templates that rewrite matching request bodies before forwarding and
//! matching response bodies before they reach the client.
//!
//! Like [`transform`](crate::transform), this module is pure configuration —
//! parsing and validation (including a template syntax check). The runtime
//! lives in `g2-middleware` (`BodyTransformLayer`), where every template is
//! compiled once at route-build time so the hot path renders prebuilt
//! programs (ADR-0001). Design decisions: ADR-0007.
//!
//! # Semantics
//!
//! Patterns are regexes searched (unanchored) against the **full client
//! request path**, listen path included, matching the
//! [`endpoints`](crate::endpoints) lists; an empty `methods` list applies to
//! every method; the first matching rule per direction wins. Response rules
//! match on the *request's* method and path — a transform targets an
//! endpoint, not a status code. Matching bodies are buffered whole (bounded)
//! and re-emitted as the rendered template output; transforms **fail
//! closed** — a body over the cap or a failing render rejects the exchange
//! instead of passing the original body through (see the layer docs for the
//! exact statuses).

use http::header::HeaderValue;
use serde::{Deserialize, Serialize};

use crate::endpoints::{validate_methods, validate_pattern};
use crate::Error;

/// Default cap on a buffered upstream response body: 1 MiB, matching the
/// request-side default and [`CacheConfig`](crate::CacheConfig).
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: u64 = 1_048_576;

fn default_max_response_body_bytes() -> u64 {
    DEFAULT_MAX_RESPONSE_BODY_BYTES
}

fn default_content_type() -> String {
    "application/json".to_owned()
}

fn is_default_content_type(value: &str) -> bool {
    value == "application/json"
}

fn is_default_max_response_body_bytes(value: &u64) -> bool {
    *value == DEFAULT_MAX_RESPONSE_BODY_BYTES
}

/// One body-transform rule: requests (or responses) matching it have their
/// body replaced by the rendered `template`.
///
/// The template is minijinja (Jinja2 syntax), inline in the definition —
/// there is no file/blob mode (a deliberate simplification: definitions
/// stay self-contained). It renders against `body` (the payload parsed as
/// JSON, `none` when it does not parse), `raw` (the payload as a lossy UTF-8
/// string) and `_g2` (request metadata: `method`, `path`, `query`,
/// `headers`, `session`, plus `status` for response rules).
///
/// # Example (JSON)
///
/// ```json
/// {
///   "pattern": "^/users/orders$",
///   "methods": ["POST"],
///   "template": "{\"order\": {{ body.id | tojson }}, \"src\": \"g2\"}",
///   "content_type": "application/json"
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyTransformRule {
    /// Regex searched against the full client request path.
    pub pattern: String,

    /// Methods the rule applies to (case-insensitive). Empty = every method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,

    /// The minijinja template whose rendered output replaces the body.
    pub template: String,

    /// `Content-Type` set on the transformed message. Defaults to
    /// `application/json`.
    #[serde(
        default = "default_content_type",
        skip_serializing_if = "is_default_content_type"
    )]
    pub content_type: String,
}

impl BodyTransformRule {
    /// Validates one rule; `api` names the owning definition, `direction`
    /// the owning list (`request`/`response`) and `index` the rule's
    /// position in errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the pattern is not a
    /// valid regex, a method is not a standard HTTP method, the template is
    /// empty or has a syntax error, or `content_type` is not a valid header
    /// value.
    pub fn validate(&self, api: &str, direction: &str, index: usize) -> Result<(), Error> {
        let list = format!("transform_body.{direction}");
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        validate_pattern(&self.pattern, api, &list, index)?;
        validate_methods(&self.methods, api, &list, index)?;
        if self.template.is_empty() {
            return Err(fail(format!(
                "`{list}[{index}].template` must not be empty"
            )));
        }
        if let Err(err) = minijinja::Environment::new().template_from_str(&self.template) {
            return Err(fail(format!(
                "`{list}[{index}].template` is not a valid minijinja template: {err}"
            )));
        }
        if HeaderValue::from_str(&self.content_type).is_err() {
            return Err(fail(format!(
                "`{list}[{index}].content_type` is not a valid header value"
            )));
        }
        Ok(())
    }
}

/// Request and response body transforms for one API.
///
/// Configured on an [`ApiDefinition`](crate::ApiDefinition) as
/// `transform_body`. Applied only to traffic that reaches the forwarding
/// stage — gateway-generated rejections (401/403/429) are never transformed,
/// while mock responses and cached responses are, matching the
/// header-transform contract.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "request": [
///     { "pattern": "^/users/orders$", "methods": ["POST"],
///       "template": "{\"wrapped\": {{ raw | tojson }}}" }
///   ],
///   "response": [
///     { "pattern": "^/users/",
///       "template": "{\"data\": {{ body | tojson }}, \"status\": {{ _g2.status }}}" }
///   ],
///   "max_response_body_bytes": 1048576
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyTransforms {
    /// Rules for upstream-bound request bodies. First match wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request: Vec<BodyTransformRule>,

    /// Rules for client-bound response bodies, matched on the *request's*
    /// method and path. First match wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response: Vec<BodyTransformRule>,

    /// Cap on a buffered upstream response body; a matching response larger
    /// than this is rejected with `502` (transforms fail closed). Defaults
    /// to 1 MiB. Request bodies are capped by the API's
    /// `max_request_body_bytes` (same 1 MiB default) instead.
    #[serde(
        default = "default_max_response_body_bytes",
        skip_serializing_if = "is_default_max_response_body_bytes"
    )]
    pub max_response_body_bytes: u64,
}

impl BodyTransforms {
    /// Whether the block declares no rules at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.request.is_empty() && self.response.is_empty()
    }

    /// Validates the whole block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the block is present but
    /// declares no rules, `max_response_body_bytes` is zero, or any rule is
    /// invalid (see [`BodyTransformRule::validate`]).
    pub fn validate(&self, api: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        if self.is_empty() {
            return Err(fail(
                "`transform_body` must declare at least one request or response rule \
                 (omit the block entirely to disable body transforms)"
                    .to_owned(),
            ));
        }
        if self.max_response_body_bytes == 0 {
            return Err(fail(
                "`transform_body.max_response_body_bytes` must be greater than zero".to_owned(),
            ));
        }
        for (direction, rules) in [("request", &self.request), ("response", &self.response)] {
            for (index, rule) in rules.iter().enumerate() {
                rule.validate(api, direction, index)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, template: &str) -> BodyTransformRule {
        BodyTransformRule {
            pattern: pattern.into(),
            methods: vec![],
            template: template.into(),
            content_type: default_content_type(),
        }
    }

    #[test]
    fn rule_defaults_and_round_trip() {
        let parsed: BodyTransformRule =
            serde_json::from_str(r#"{"pattern": "^/a$", "template": "{{ raw }}"}"#)
                .expect("parses");
        assert!(parsed.methods.is_empty());
        assert_eq!(parsed.content_type, "application/json");

        let json = serde_json::to_string(&parsed).expect("serializes");
        assert!(!json.contains("methods"), "got: {json}");
        assert!(!json.contains("content_type"), "got: {json}");
        assert_eq!(
            serde_json::from_str::<BodyTransformRule>(&json).expect("back"),
            parsed
        );

        let full: BodyTransformRule = serde_json::from_str(
            r#"{
                "pattern": "^/a$",
                "methods": ["POST"],
                "template": "hi",
                "content_type": "text/plain"
            }"#,
        )
        .expect("parses");
        let json = serde_json::to_string(&full).expect("serializes");
        assert!(json.contains("text/plain"), "non-default kept: {json}");
        assert_eq!(
            serde_json::from_str::<BodyTransformRule>(&json).expect("back"),
            full
        );
    }

    #[test]
    fn block_defaults_and_round_trip() {
        let block: BodyTransforms =
            serde_json::from_str(r#"{"request": [{"pattern": "^/a$", "template": "{{ raw }}"}]}"#)
                .expect("parses");
        assert_eq!(
            block.max_response_body_bytes,
            DEFAULT_MAX_RESPONSE_BODY_BYTES
        );
        block.validate("api").expect("valid");

        let json = serde_json::to_string(&block).expect("serializes");
        assert!(!json.contains("max_response_body_bytes"), "got: {json}");
        assert!(!json.contains("response"), "got: {json}");
        assert_eq!(
            serde_json::from_str::<BodyTransforms>(&json).expect("back"),
            block
        );
    }

    #[test]
    fn rules_validate() {
        rule("^/a$", "{{ body | tojson }}")
            .validate("api", "request", 0)
            .expect("valid");

        let err = rule("(", "x")
            .validate("api", "request", 2)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("transform_body.request[2].pattern"),
            "got: {err}"
        );

        let mut r = rule("^/a$", "x");
        r.methods = vec!["FETCH".into()];
        let err = r.validate("api", "response", 1).unwrap_err().to_string();
        assert!(
            err.contains("transform_body.response[1].methods"),
            "got: {err}"
        );

        let err = rule("^/a$", "")
            .validate("api", "request", 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("template` must not be empty"), "got: {err}");

        let err = rule("^/a$", "{{ unclosed")
            .validate("api", "request", 0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("transform_body.request[0].template"),
            "syntax error names the rule: {err}"
        );

        let mut r = rule("^/a$", "x");
        r.content_type = "line\nbreak".into();
        let err = r.validate("api", "request", 0).unwrap_err().to_string();
        assert!(err.contains("content_type"), "got: {err}");
    }

    #[test]
    fn block_validation_rejects_empty_and_zero_cap() {
        let empty: BodyTransforms = serde_json::from_str("{}").expect("parses");
        let err = empty.validate("api").unwrap_err().to_string();
        assert!(err.contains("at least one"), "got: {err}");

        let mut block = BodyTransforms {
            request: vec![rule("^/a$", "x")],
            response: vec![],
            max_response_body_bytes: 0,
        };
        let err = block.validate("api").unwrap_err().to_string();
        assert!(err.contains("max_response_body_bytes"), "got: {err}");
        block.max_response_body_bytes = 1;
        block.validate("api").expect("valid");
    }
}
