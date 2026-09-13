//! Access-control configuration (milestone M6): CORS, IP allow/deny lists,
//! and request size limits for one API.
//!
//! Like [`transform`](crate::transform) and [`endpoints`](crate::endpoints),
//! this module is pure configuration — parsing and validation. Runtime
//! enforcement lives in `g2-middleware` (`CorsLayer`, `IpFilterLayer`,
//! `RequestSizeLimitLayer`), precompiled at route-build time (ADR-0001).

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::transform::TRANSFORM_METHODS;
use crate::Error;

/// Methods a CORS-enabled API allows when the definition does not list any:
/// the fetch-spec CORS-safelisted methods.
pub const DEFAULT_CORS_METHODS: [&str; 3] = ["GET", "HEAD", "POST"];

fn default_cors_methods() -> Vec<String> {
    DEFAULT_CORS_METHODS
        .iter()
        .map(|m| (*m).to_owned())
        .collect()
}

/// Cross-Origin Resource Sharing settings for one API.
///
/// When configured, the gateway answers preflight `OPTIONS` requests itself
/// (unless `options_passthrough` is set) and decorates responses — gateway
/// rejections like `401`/`429` included, so browsers can read them — with
/// the appropriate `Access-Control-*` headers. Requests from origins not
/// listed here are still forwarded, just without CORS headers: enforcement
/// is the browser's job, access control is the IP/path lists' and auth's.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "allowed_origins": ["https://app.example.com"],
///   "allowed_methods": ["GET", "POST", "DELETE"],
///   "allowed_headers": ["Authorization", "Content-Type"],
///   "allow_credentials": true,
///   "max_age_secs": 600
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Origins allowed to make cross-origin requests, e.g.
    /// `https://app.example.com` (scheme, host, optional port — no path).
    /// The single entry `"*"` allows every origin, but cannot be combined
    /// with other origins or with `allow_credentials`.
    pub allowed_origins: Vec<String>,

    /// Methods advertised to preflight requests. Defaults to the
    /// CORS-safelisted methods ([`DEFAULT_CORS_METHODS`]).
    #[serde(default = "default_cors_methods")]
    pub allowed_methods: Vec<String>,

    /// Request headers advertised to preflight requests. Empty (the
    /// default) mirrors whatever headers the preflight asks for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_headers: Vec<String>,

    /// Response headers browsers may expose to cross-origin scripts
    /// (`Access-Control-Expose-Headers`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exposed_headers: Vec<String>,

    /// Whether `Access-Control-Allow-Credentials: true` is sent. Requires
    /// explicit `allowed_origins` (the wildcard is rejected — browsers
    /// refuse that combination anyway).
    #[serde(default)]
    pub allow_credentials: bool,

    /// Seconds browsers may cache a preflight result
    /// (`Access-Control-Max-Age`). Omitted from responses when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,

    /// When `true`, preflight `OPTIONS` requests are forwarded to the
    /// upstream instead of being answered by the gateway. Responses are
    /// still decorated.
    #[serde(default)]
    pub options_passthrough: bool,
}

impl CorsConfig {
    /// Validates the CORS settings; `api` names the owning definition in
    /// errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the origin list is
    /// empty or malformed, the wildcard is combined with other origins or
    /// with credentials, a method is not a standard HTTP method, or a
    /// header name does not parse.
    pub fn validate(&self, api: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        if self.allowed_origins.is_empty() {
            return Err(fail("`cors.allowed_origins` must not be empty".into()));
        }
        let wildcard = self.allowed_origins.iter().any(|o| o == "*");
        if wildcard && self.allowed_origins.len() > 1 {
            return Err(fail(
                "`cors.allowed_origins` must be either `[\"*\"]` or a list of \
                 explicit origins, not both"
                    .into(),
            ));
        }
        if wildcard && self.allow_credentials {
            return Err(fail(
                "`cors.allow_credentials` cannot be combined with the `*` origin \
                 (browsers reject that combination)"
                    .into(),
            ));
        }
        for origin in &self.allowed_origins {
            if origin != "*" && !is_valid_origin(origin) {
                return Err(fail(format!(
                    "`cors.allowed_origins` entry is not a valid origin \
                     (`scheme://host[:port]`, no path): `{origin}`"
                )));
            }
        }
        if self.allowed_methods.is_empty() {
            return Err(fail("`cors.allowed_methods` must not be empty".into()));
        }
        for method in &self.allowed_methods {
            if !TRANSFORM_METHODS
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
            {
                return Err(fail(format!(
                    "`cors.allowed_methods` must contain only standard HTTP methods \
                     ({}), got `{method}`",
                    TRANSFORM_METHODS.join(", ")
                )));
            }
        }
        for (field, names) in [
            ("allowed_headers", &self.allowed_headers),
            ("exposed_headers", &self.exposed_headers),
        ] {
            for name in names {
                if http::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
                    return Err(fail(format!(
                        "`cors.{field}` entry is not a valid header name: `{name}`"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Whether `origin` looks like a serialized origin: `scheme://host[:port]`
/// with an `http`/`https` scheme, no userinfo, and no path or query.
fn is_valid_origin(origin: &str) -> bool {
    let Ok(uri) = origin.parse::<http::Uri>() else {
        return false;
    };
    let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) else {
        return false;
    };
    // `Uri` normalizes an empty path to `/`, so reconstructing the origin
    // and comparing catches any path, query, or trailing slash in one go.
    matches!(scheme, "http" | "https")
        && !authority.as_str().contains('@')
        && origin == format!("{scheme}://{authority}")
}

/// Parses one IP-list entry: a plain address (`10.0.0.1`, `2001:db8::1`) or
/// a CIDR network (`10.0.0.0/8`, `2001:db8::/32`). A plain address becomes
/// the full-length network containing only itself.
#[must_use]
pub fn parse_ip_entry(entry: &str) -> Option<IpNet> {
    if let Ok(net) = IpNet::from_str(entry) {
        return Some(net);
    }
    entry.parse::<IpAddr>().ok().map(IpNet::from)
}

/// Validates an `allow_ips`/`block_ips` list; `api` names the owning
/// definition and `field` the list in errors.
///
/// # Errors
///
/// Returns [`Error::InvalidApiDefinition`] when an entry is neither an IP
/// address nor a CIDR network.
pub fn validate_ip_list(list: &[String], api: &str, field: &str) -> Result<(), Error> {
    for entry in list {
        if parse_ip_entry(entry).is_none() {
            return Err(Error::InvalidApiDefinition {
                api: api.to_owned(),
                reason: format!("`{field}` entry is not an IP address or CIDR network: `{entry}`"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cors(json: &str) -> CorsConfig {
        serde_json::from_str(json).expect("valid CORS JSON")
    }

    #[test]
    fn minimal_cors_gets_defaults_and_round_trips() {
        let config = cors(r#"{"allowed_origins": ["https://app.example.com"]}"#);
        assert_eq!(config.allowed_methods, DEFAULT_CORS_METHODS.to_vec());
        assert!(config.allowed_headers.is_empty());
        assert!(!config.allow_credentials && !config.options_passthrough);
        assert!(config.max_age_secs.is_none());
        config.validate("api").expect("valid");

        let json = serde_json::to_string(&config).expect("serializes");
        assert_eq!(
            serde_json::from_str::<CorsConfig>(&json).expect("back"),
            config
        );
    }

    #[test]
    fn wildcard_origin_is_valid_without_credentials() {
        cors(r#"{"allowed_origins": ["*"]}"#)
            .validate("api")
            .expect("valid");
    }

    #[test]
    fn invalid_cors_configs_are_rejected() {
        for (json, hint) in [
            (r#"{"allowed_origins": []}"#, "empty origins"),
            (
                r#"{"allowed_origins": ["*", "https://a.example"]}"#,
                "wildcard mixed with explicit origins",
            ),
            (
                r#"{"allowed_origins": ["*"], "allow_credentials": true}"#,
                "wildcard with credentials",
            ),
            (
                r#"{"allowed_origins": ["https://a.example/path"]}"#,
                "origin with a path",
            ),
            (
                r#"{"allowed_origins": ["a.example"]}"#,
                "origin without a scheme",
            ),
            (
                r#"{"allowed_origins": ["ftp://a.example"]}"#,
                "non-http scheme",
            ),
            (
                r#"{"allowed_origins": ["https://user@a.example"]}"#,
                "origin with userinfo",
            ),
            (
                r#"{"allowed_origins": ["https://a.example"], "allowed_methods": []}"#,
                "explicitly empty methods",
            ),
            (
                r#"{"allowed_origins": ["https://a.example"], "allowed_methods": ["FETCH"]}"#,
                "non-standard method",
            ),
            (
                r#"{"allowed_origins": ["https://a.example"], "allowed_headers": ["bad name"]}"#,
                "invalid header name",
            ),
        ] {
            assert!(
                cors(json).validate("api").is_err(),
                "expected rejection: {hint}"
            );
        }
    }

    #[test]
    fn origins_with_ports_are_valid() {
        cors(r#"{"allowed_origins": ["http://localhost:3000", "https://a.example:8443"]}"#)
            .validate("api")
            .expect("valid");
    }

    #[test]
    fn ip_entries_parse_as_addresses_or_networks() {
        for entry in ["10.0.0.1", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32"] {
            assert!(
                parse_ip_entry(entry).is_some(),
                "expected `{entry}` to parse"
            );
        }
        // A plain address matches only itself.
        let net = parse_ip_entry("10.0.0.1").expect("parses");
        assert!(net.contains(&"10.0.0.1".parse::<IpAddr>().expect("ip")));
        assert!(!net.contains(&"10.0.0.2".parse::<IpAddr>().expect("ip")));
    }

    #[test]
    fn ip_lists_validate() {
        validate_ip_list(
            &["10.0.0.0/8".into(), "192.168.1.1".into()],
            "api",
            "allow_ips",
        )
        .expect("valid");

        let err = validate_ip_list(&["not-an-ip".into()], "api", "block_ips")
            .unwrap_err()
            .to_string();
        assert!(err.contains("block_ips"), "got: {err}");
    }
}
