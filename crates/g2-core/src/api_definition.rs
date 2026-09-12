//! The [`ApiDefinition`] model: one upstream API exposed through the gateway.

use http::Uri;
use serde::{Deserialize, Serialize};

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

/// One API proxied by the gateway.
///
/// This is the unit of configuration: requests whose path falls under
/// `listen_path` are forwarded to `target_url`.
///
/// Definitions are currently loaded from files (see [`crate::loader`]); later
/// milestones add Redis-backed storage managed through the admin API.
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
    fn target_uri_round_trips() {
        let def = parse(minimal_json());
        let uri = def.target_uri();
        assert_eq!(uri.host(), Some("users.internal"));
        assert_eq!(uri.port_u16(), Some(8000));
    }
}
