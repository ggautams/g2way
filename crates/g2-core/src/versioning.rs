//! API versioning: version selection and per-version definition overrides.
//!
//! An [`ApiDefinition`] with a [`VersioningConfig`]
//! serves several *versions* behind one listen path. The requested version is
//! named by a request header or query parameter ([`VersionLocation`]); each
//! version is the base definition with a [`VersionOverrides`] applied on top
//! ([`VersioningConfig::apply`]). Requests naming no version fall back to
//! `default_version` when configured; a request that resolves to no version,
//! an unknown version, or an expired version is rejected with `403`.
//!
//! Overrides are wholesale: a present field **replaces** the base field, an
//! absent field inherits it — the same replace-don't-merge rule policies use
//! for sessions. An explicitly empty list (e.g. `"url_rewrites": []`)
//! therefore clears the base list for that version.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::api_definition::{CacheConfig, CircuitBreakerConfig, HealthCheckConfig};
use crate::endpoints::{EndpointRateLimit, MockResponse, PathRule};
use crate::graphql::GraphQlConfig;
use crate::transform::{HeaderTransforms, UrlRewriteRule};
use crate::{ApiDefinition, Error};

/// Header/query-parameter name used to select a version when a definition
/// does not name one.
pub const DEFAULT_VERSION_KEY: &str = "x-api-version";

fn default_version_key() -> String {
    DEFAULT_VERSION_KEY.to_owned()
}

/// Where the requested version name is read from.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionLocation {
    /// A request header (the default), e.g. `X-Api-Version: v2`.
    #[default]
    Header,
    /// A query parameter, e.g. `?version=v2`. The value is matched verbatim
    /// (no percent-decoding), like the auth-token query carrier.
    QueryParam,
}

/// Versioning settings for one API definition.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersioningConfig {
    /// Where the version name is read from. Defaults to a header.
    #[serde(default)]
    pub location: VersionLocation,

    /// The header or query-parameter name carrying the version. Defaults to
    /// [`DEFAULT_VERSION_KEY`].
    #[serde(default = "default_version_key")]
    pub key: String,

    /// Version used when the request names none. Unset means a version is
    /// required: requests without one are rejected with `403`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_version: Option<String>,

    /// The versions this API serves, by name. Must not be empty.
    pub versions: BTreeMap<String, VersionOverrides>,
}

/// Per-version overrides applied on top of the base definition.
///
/// Every field is optional: present replaces the base value wholesale,
/// absent inherits it. `Option`-typed base fields (`transform_headers`,
/// `transform_method`) can be overridden but not cleared per version — keep
/// them off the base definition if only some versions want them.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VersionOverrides {
    /// Unix time (seconds) after which this version is expired: requests for
    /// it are rejected with `403`. The boundary is inclusive, like key
    /// session expiry. Unset means the version never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Replacement upstream base URL for this version. Rejected at
    /// validation time when the version's
    /// effective `target_list` is non-empty — load-balanced traffic never
    /// reads `target_url`, so the override would silently do nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_url: Option<String>,

    /// Replacement load-balancing target list for this version. An empty
    /// list disables load balancing for the version, reverting it to its
    /// effective `target_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_list: Option<Vec<String>>,

    /// Replacement upstream timeout for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_timeout_ms: Option<u64>,

    /// Replacement header transforms for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform_headers: Option<HeaderTransforms>,

    /// Replacement URL rewrite rules for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_rewrites: Option<Vec<UrlRewriteRule>>,

    /// Replacement method override for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform_method: Option<String>,

    /// Replacement allow-path rules for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_paths: Option<Vec<PathRule>>,

    /// Replacement block-path rules for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_paths: Option<Vec<PathRule>>,

    /// Replacement ignore-auth-path rules for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_auth_paths: Option<Vec<PathRule>>,

    /// Replacement mock-response rules for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mock_responses: Option<Vec<MockResponse>>,

    /// Replacement endpoint rate limits for this version (replaced
    /// wholesale). Each version's counters live under their own scope, so
    /// versions never share allowances.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_rate_limits: Option<Vec<EndpointRateLimit>>,

    /// Replacement upstream health-check settings for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,

    /// Replacement circuit-breaker settings for this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Replacement upstream retry count for this version (`0` disables
    /// retries for the version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_retries: Option<u32>,

    /// Replacement response-cache settings for this version. Each version
    /// caches under its own scope, so versions never share entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheConfig>,

    /// Replacement GraphQL settings for this version (schema, protections,
    /// playground, persisted queries — replaced wholesale).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphql: Option<GraphQlConfig>,
}

impl VersioningConfig {
    /// Validates the versioning settings against their base definition,
    /// including every effective per-version definition.
    ///
    /// Called by [`ApiDefinition::validate`] after the base fields have
    /// passed, so a failure inside an effective definition is attributable
    /// to the version's overrides and the error names the version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the key is invalid for
    /// the location, `versions` is empty, a version name is empty or
    /// whitespace-padded, `default_version` names no configured version, or
    /// a version's effective definition fails validation.
    pub fn validate(&self, base: &ApiDefinition) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: base.api_id.clone(),
            reason,
        };

        match self.location {
            VersionLocation::Header => {
                if http::header::HeaderName::from_bytes(self.key.as_bytes()).is_err() {
                    return Err(fail(format!(
                        "`versioning.key` is not a valid header name: `{}`",
                        self.key
                    )));
                }
            }
            VersionLocation::QueryParam => {
                if self.key.trim().is_empty() {
                    return Err(fail("`versioning.key` must not be empty".into()));
                }
            }
        }
        if self.versions.is_empty() {
            return Err(fail(
                "`versioning.versions` must define at least one version".into(),
            ));
        }
        for name in self.versions.keys() {
            // The request-side value is trimmed before matching, so a padded
            // or empty name could never be selected.
            if name.is_empty() || name.trim() != name {
                return Err(fail(format!(
                    "version name `{name}` must be non-empty without surrounding whitespace"
                )));
            }
        }
        if let Some(default) = &self.default_version {
            if !self.versions.contains_key(default) {
                return Err(fail(format!(
                    "`versioning.default_version` (`{default}`) is not a configured version"
                )));
            }
        }
        for (name, overrides) in &self.versions {
            let effective = self
                .apply(base, name)
                .expect("apply() succeeds for every key of the versions map");
            if overrides.target_url.is_some() && !effective.target_list.is_empty() {
                return Err(fail(format!(
                    "version `{name}`: the `target_url` override has no effect while the \
                     effective `target_list` is non-empty; override `target_list` instead"
                )));
            }
            if let Err(Error::InvalidApiDefinition { api, reason }) = effective.validate() {
                return Err(Error::InvalidApiDefinition {
                    api,
                    reason: format!("version `{name}`: {reason}"),
                });
            }
        }
        Ok(())
    }

    /// The base definition with `version`'s overrides applied and versioning
    /// removed — the definition one version's traffic is actually served
    /// with. `None` when `version` is not configured.
    #[must_use]
    pub fn apply(&self, base: &ApiDefinition, version: &str) -> Option<ApiDefinition> {
        let overrides = self.versions.get(version)?;
        let mut def = base.clone();
        def.versioning = None;
        if let Some(v) = &overrides.target_url {
            def.target_url = v.clone();
        }
        if let Some(v) = &overrides.target_list {
            def.target_list = v.clone();
        }
        if let Some(v) = overrides.upstream_timeout_ms {
            def.upstream_timeout_ms = v;
        }
        if let Some(v) = &overrides.transform_headers {
            def.transform_headers = Some(v.clone());
        }
        if let Some(v) = &overrides.url_rewrites {
            def.url_rewrites = v.clone();
        }
        if let Some(v) = &overrides.transform_method {
            def.transform_method = Some(v.clone());
        }
        if let Some(v) = &overrides.allow_paths {
            def.allow_paths = v.clone();
        }
        if let Some(v) = &overrides.block_paths {
            def.block_paths = v.clone();
        }
        if let Some(v) = &overrides.ignore_auth_paths {
            def.ignore_auth_paths = v.clone();
        }
        if let Some(v) = &overrides.mock_responses {
            def.mock_responses = v.clone();
        }
        if let Some(v) = &overrides.endpoint_rate_limits {
            def.endpoint_rate_limits = v.clone();
        }
        if let Some(v) = &overrides.health_check {
            def.health_check = Some(v.clone());
        }
        if let Some(v) = &overrides.circuit_breaker {
            def.circuit_breaker = Some(v.clone());
        }
        if let Some(v) = overrides.upstream_retries {
            def.upstream_retries = v;
        }
        if let Some(v) = &overrides.cache {
            def.cache = Some(v.clone());
        }
        if let Some(v) = &overrides.graphql {
            def.graphql = Some(v.clone());
        }
        Some(def)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ApiDefinition {
        serde_json::from_str(
            r#"{
                "api_id": "v",
                "name": "v",
                "listen_path": "/v/",
                "target_url": "http://v.internal",
                "auth": {"mode": "keyless"}
            }"#,
        )
        .expect("valid definition")
    }

    fn versioning(json: &str) -> VersioningConfig {
        serde_json::from_str(json).expect("valid versioning JSON")
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let cfg = versioning(r#"{"versions": {"v1": {}}}"#);
        assert_eq!(cfg.location, VersionLocation::Header);
        assert_eq!(cfg.key, DEFAULT_VERSION_KEY);
        assert!(cfg.default_version.is_none());
        cfg.validate(&base()).expect("valid");
    }

    #[test]
    fn key_is_validated_per_location() {
        let cfg = versioning(r#"{"key": "bad header\n", "versions": {"v1": {}}}"#);
        assert!(cfg.validate(&base()).is_err());

        let cfg = versioning(r#"{"location": "query_param", "key": "  ", "versions": {"v1": {}}}"#);
        assert!(cfg.validate(&base()).is_err());

        // The same padded key is fine as a query parameter name pattern but
        // a valid one passes both locations.
        let cfg = versioning(r#"{"location": "query_param", "key": "v", "versions": {"v1": {}}}"#);
        cfg.validate(&base()).expect("valid");
    }

    #[test]
    fn versions_must_be_non_empty_with_clean_names() {
        let cfg = versioning(r#"{"versions": {}}"#);
        assert!(cfg.validate(&base()).is_err());

        for bad in ["", " v1", "v1 "] {
            let mut cfg = versioning(r#"{"versions": {"v1": {}}}"#);
            let overrides = cfg.versions.remove("v1").expect("seeded");
            cfg.versions.insert(bad.to_owned(), overrides);
            assert!(cfg.validate(&base()).is_err(), "name `{bad:?}` accepted");
        }
    }

    #[test]
    fn default_version_must_exist() {
        let cfg = versioning(r#"{"default_version": "v2", "versions": {"v1": {}}}"#);
        let err = cfg.validate(&base()).unwrap_err().to_string();
        assert!(err.contains("default_version"), "got: {err}");
    }

    #[test]
    fn broken_overrides_fail_naming_the_version() {
        let cfg = versioning(r#"{"versions": {"v2": {"target_url": "not-a-url"}}}"#);
        let err = cfg.validate(&base()).unwrap_err().to_string();
        assert!(err.contains("version `v2`"), "got: {err}");
        assert!(err.contains("target_url"), "got: {err}");

        let cfg = versioning(
            r#"{"versions": {"v2": {"url_rewrites": [{"pattern": "(", "rewrite": "/x"}]}}}"#,
        );
        assert!(cfg.validate(&base()).is_err());
    }

    #[test]
    fn apply_replaces_overridden_fields_and_inherits_the_rest() {
        let cfg = versioning(
            r#"{
                "versions": {
                    "v1": {},
                    "v2": {
                        "target_url": "http://v2.internal",
                        "upstream_timeout_ms": 1000,
                        "transform_method": "POST"
                    }
                }
            }"#,
        );
        let mut base = base();
        base.versioning = Some(cfg.clone());

        let v1 = cfg.apply(&base, "v1").expect("v1 configured");
        assert_eq!(v1.target_url, "http://v.internal");
        assert!(v1.versioning.is_none(), "effective defs are unversioned");

        let v2 = cfg.apply(&base, "v2").expect("v2 configured");
        assert_eq!(v2.target_url, "http://v2.internal");
        assert_eq!(v2.upstream_timeout_ms, 1000);
        assert_eq!(v2.transform_method.as_deref(), Some("POST"));
        // Inherited fields are untouched.
        assert_eq!(v2.listen_path, base.listen_path);
        assert_eq!(v2.auth, base.auth);

        assert!(cfg.apply(&base, "v3").is_none());
    }

    #[test]
    fn target_list_override_replaces_or_clears_and_guards_target_url() {
        let mut base = base();
        base.target_list = vec!["http://a.internal".into(), "http://b.internal".into()];

        // Replacing and clearing the list per version both work.
        let cfg = versioning(
            r#"{"versions": {
                "v1": {"target_list": ["http://c.internal"]},
                "v2": {"target_list": []}
            }}"#,
        );
        cfg.validate(&base).expect("valid");
        let v1 = cfg.apply(&base, "v1").expect("configured");
        assert_eq!(v1.target_list, vec!["http://c.internal".to_owned()]);
        let v2 = cfg.apply(&base, "v2").expect("configured");
        assert!(v2.target_list.is_empty(), "empty override clears the list");

        // A target_url override on a load-balanced effective definition
        // would silently do nothing — rejected, naming the version.
        let cfg = versioning(r#"{"versions": {"v2": {"target_url": "http://v2.internal"}}}"#);
        let err = cfg.validate(&base).unwrap_err().to_string();
        assert!(
            err.contains("version `v2`") && err.contains("target_list"),
            "got: {err}"
        );

        // …but overriding target_url together with an emptied list is fine.
        let cfg = versioning(
            r#"{"versions": {"v2": {"target_url": "http://v2.internal", "target_list": []}}}"#,
        );
        cfg.validate(&base).expect("valid");

        // A broken list entry fails like any invalid effective definition.
        let cfg = versioning(r#"{"versions": {"v2": {"target_list": ["nope"]}}}"#);
        assert!(cfg.validate(&base).is_err());
    }

    #[test]
    fn health_check_override_replaces_the_base_settings() {
        let mut base = base();
        base.target_list = vec!["http://a.internal".into(), "http://b.internal".into()];
        base.health_check =
            Some(serde_json::from_str(r#"{"interval_ms": 5000}"#).expect("health JSON"));

        let cfg = versioning(
            r#"{"versions": {
                "v1": {},
                "v2": {"health_check": {"path": "/status", "interval_ms": 1000}}
            }}"#,
        );
        cfg.validate(&base).expect("valid");
        let v1 = cfg.apply(&base, "v1").expect("configured");
        assert_eq!(
            v1.health_check.as_ref().expect("inherited").interval_ms,
            5000
        );
        let v2 = cfg.apply(&base, "v2").expect("configured");
        let hc = v2.health_check.as_ref().expect("overridden");
        assert_eq!((hc.path.as_str(), hc.interval_ms), ("/status", 1000));

        // A broken override fails validation naming the version.
        let cfg = versioning(r#"{"versions": {"v2": {"health_check": {"interval_ms": 0}}}}"#);
        let err = cfg.validate(&base).unwrap_err().to_string();
        assert!(err.contains("version `v2`"), "got: {err}");
    }

    #[test]
    fn circuit_breaker_and_retries_overrides_replace_the_base() {
        let mut base = base();
        base.circuit_breaker =
            Some(serde_json::from_str(r#"{"failure_threshold": 3}"#).expect("breaker JSON"));
        base.upstream_retries = 2;

        let cfg = versioning(
            r#"{"versions": {
                "v1": {},
                "v2": {"circuit_breaker": {"cooldown_ms": 5000}, "upstream_retries": 0}
            }}"#,
        );
        cfg.validate(&base).expect("valid");
        let v1 = cfg.apply(&base, "v1").expect("configured");
        assert_eq!(
            v1.circuit_breaker
                .as_ref()
                .expect("inherited")
                .failure_threshold,
            3
        );
        assert_eq!(v1.upstream_retries, 2);
        let v2 = cfg.apply(&base, "v2").expect("configured");
        let cb = v2.circuit_breaker.as_ref().expect("overridden");
        assert_eq!((cb.failure_threshold, cb.cooldown_ms), (5, 5000));
        assert_eq!(v2.upstream_retries, 0, "override disables retries");

        // A broken override fails validation naming the version.
        let cfg =
            versioning(r#"{"versions": {"v2": {"circuit_breaker": {"failure_threshold": 0}}}}"#);
        let err = cfg.validate(&base).unwrap_err().to_string();
        assert!(err.contains("version `v2`"), "got: {err}");
        let cfg = versioning(r#"{"versions": {"v2": {"upstream_retries": 99}}}"#);
        assert!(cfg.validate(&base).is_err());
    }

    #[test]
    fn cache_override_replaces_the_base_settings() {
        let mut base = base();
        base.cache = Some(serde_json::from_str(r#"{"ttl_secs": 30}"#).expect("cache JSON"));

        let cfg = versioning(
            r#"{"versions": {
                "v1": {},
                "v2": {"cache": {"ttl_secs": 5, "max_body_bytes": 1024}}
            }}"#,
        );
        cfg.validate(&base).expect("valid");
        let v1 = cfg.apply(&base, "v1").expect("configured");
        assert_eq!(v1.cache.as_ref().expect("inherited").ttl_secs, 30);
        let v2 = cfg.apply(&base, "v2").expect("configured");
        let cache = v2.cache.as_ref().expect("overridden");
        assert_eq!((cache.ttl_secs, cache.max_body_bytes), (5, 1024));

        // A broken override fails validation naming the version.
        let cfg = versioning(r#"{"versions": {"v2": {"cache": {"ttl_secs": 0}}}}"#);
        let err = cfg.validate(&base).unwrap_err().to_string();
        assert!(err.contains("version `v2`"), "got: {err}");
    }

    #[test]
    fn graphql_override_replaces_the_base_settings() {
        let mut base = base();
        base.graphql = Some(
            serde_json::from_str(r#"{"schema": "type Query { a: String }"}"#).expect("gql JSON"),
        );

        let cfg = versioning(
            r#"{"versions": {
                "v1": {},
                "v2": {"graphql": {"schema": "type Query { b: String }", "max_query_depth": 3}}
            }}"#,
        );
        cfg.validate(&base).expect("valid");
        let v1 = cfg.apply(&base, "v1").expect("configured");
        assert!(v1
            .graphql
            .as_ref()
            .expect("inherited")
            .schema
            .contains("a: String"));
        let v2 = cfg.apply(&base, "v2").expect("configured");
        let gql = v2.graphql.as_ref().expect("overridden");
        assert!(gql.schema.contains("b: String"));
        assert_eq!(gql.max_query_depth, Some(3));

        // A broken override fails validation naming the version.
        let cfg = versioning(r#"{"versions": {"v2": {"graphql": {"schema": "type Query {"}}}}"#);
        let err = cfg.validate(&base).unwrap_err().to_string();
        assert!(err.contains("version `v2`"), "got: {err}");
    }

    #[test]
    fn endpoint_rate_limit_override_replaces_the_base_and_is_validated() {
        let cfg = versioning(
            r#"{
                "versions": {
                    "v1": {},
                    "v2": {"endpoint_rate_limits": [
                        {"pattern": "^/v/search",
                         "rate": {"requests": 3, "per_seconds": 30}}
                    ]}
                }
            }"#,
        );
        let mut base = base();
        base.endpoint_rate_limits = vec![EndpointRateLimit {
            pattern: "^/v/".into(),
            methods: vec![],
            rate: crate::session::RateLimit {
                requests: 100,
                per_seconds: 60,
            },
        }];
        base.versioning = Some(cfg.clone());
        base.validate().expect("valid");

        let v1 = cfg.apply(&base, "v1").expect("v1 configured");
        assert_eq!(v1.endpoint_rate_limits, base.endpoint_rate_limits);

        let v2 = cfg.apply(&base, "v2").expect("v2 configured");
        assert_eq!(v2.endpoint_rate_limits.len(), 1);
        assert_eq!(v2.endpoint_rate_limits[0].rate.requests, 3);

        let broken = versioning(
            r#"{"versions": {"v2": {"endpoint_rate_limits": [
                {"pattern": "(", "rate": {"requests": 3, "per_seconds": 30}}
            ]}}}"#,
        );
        let err = broken.validate(&base).unwrap_err().to_string();
        assert!(err.contains("version `v2`"), "got: {err}");
        assert!(
            err.contains("endpoint_rate_limits[0].pattern"),
            "got: {err}"
        );
    }

    #[test]
    fn apply_with_an_empty_list_clears_the_base_list() {
        let mut base = base();
        base.url_rewrites = vec![UrlRewriteRule {
            pattern: "^/v/x$".into(),
            rewrite: "/y".into(),
        }];
        let cfg = versioning(r#"{"versions": {"v2": {"url_rewrites": []}}}"#);
        let v2 = cfg.apply(&base, "v2").expect("configured");
        assert!(v2.url_rewrites.is_empty());
    }

    #[test]
    fn overrides_stay_off_the_wire_when_unset() {
        let json =
            serde_json::to_string(&versioning(r#"{"versions": {"v1": {}}}"#)).expect("serializes");
        for field in ["expires_at", "target_url", "default_version"] {
            assert!(!json.contains(field), "`{field}` serialized when unset");
        }
        assert!(json.contains(DEFAULT_VERSION_KEY), "key default persisted");
    }
}
