//! The [`ApiDefinition`] model: one upstream API exposed through the gateway.

use std::collections::BTreeMap;

use http::Uri;
use serde::{Deserialize, Serialize};

use crate::body_transform::BodyTransforms;
use crate::endpoints::{EndpointRateLimit, MockResponse, PathRule};
use crate::graphql::GraphQlConfig;
use crate::plugins::PluginsConfig;
use crate::security::{self, CorsConfig};
use crate::transform::{self, HeaderTransforms, UrlRewriteRule};
use crate::versioning::VersioningConfig;
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

/// Seconds between background JWKS re-fetches when a definition sets
/// `jwks_url` without a `jwks_refresh_secs`.
pub const DEFAULT_JWKS_REFRESH_SECS: u64 = 300;

/// Claim the OIDC mode reads as the OAuth2 client id (for policy mapping)
/// when a definition does not name one.
pub const DEFAULT_OIDC_POLICY_CLAIM: &str = "azp";

fn default_oidc_policy_claim() -> String {
    DEFAULT_OIDC_POLICY_CLAIM.to_owned()
}

/// Seconds of `Date`-header clock skew the hmac mode tolerates when a
/// definition does not set `allowed_clock_skew_secs`.
pub const DEFAULT_HMAC_CLOCK_SKEW_SECS: u64 = 300;

fn default_hmac_clock_skew() -> Option<u64> {
    Some(DEFAULT_HMAC_CLOCK_SKEW_SECS)
}

fn default_hmac_algorithms() -> Vec<HmacAlgorithm> {
    vec![
        HmacAlgorithm::HmacSha256,
        HmacAlgorithm::HmacSha384,
        HmacAlgorithm::HmacSha512,
    ]
}

/// Realm the basic-auth mode advertises in `WWW-Authenticate` challenges
/// when a definition does not name one.
pub const DEFAULT_BASIC_AUTH_REALM: &str = "g2way";

fn default_basic_auth_realm() -> String {
    DEFAULT_BASIC_AUTH_REALM.to_owned()
}

/// Path probed by upstream health checks when a definition does not name one.
pub const DEFAULT_HEALTH_CHECK_PATH: &str = "/";

fn default_health_check_path() -> String {
    DEFAULT_HEALTH_CHECK_PATH.to_owned()
}

fn default_health_check_interval_ms() -> u64 {
    10_000
}

fn default_health_check_timeout_ms() -> u64 {
    2_000
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    2
}

/// Active upstream health checking with eviction (see
/// [`ApiDefinition::health_check`]).
///
/// Each gateway pod probes every upstream address of the API on a fixed
/// interval with `GET {address base path}{path}`; only a `2xx` answer within
/// `timeout_ms` counts as healthy. An address failing `unhealthy_threshold`
/// consecutive probes is evicted from the load-balancing rotation until it
/// passes `healthy_threshold` consecutive probes again.
///
/// Eviction never empties the pool: when every address is evicted, requests
/// fall back to the plain rotation (a dead upstream then answers `502`
/// exactly like an unchecked one), so probing a single-target API observes
/// health without ever refusing traffic.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Path probed on each upstream address, joined onto the address's own
    /// base path. Must start with `/`; defaults to
    /// [`DEFAULT_HEALTH_CHECK_PATH`]. May carry a query string.
    #[serde(default = "default_health_check_path")]
    pub path: String,

    /// Milliseconds between probe rounds (per pod). Defaults to `10000`.
    #[serde(default = "default_health_check_interval_ms")]
    pub interval_ms: u64,

    /// Milliseconds a probe may take before counting as a failure.
    /// Defaults to `2000`.
    #[serde(default = "default_health_check_timeout_ms")]
    pub timeout_ms: u64,

    /// Consecutive probe failures after which an address is evicted from
    /// the rotation. Defaults to `3`.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Consecutive probe successes after which an evicted address rejoins
    /// the rotation. Defaults to `2`.
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

impl HealthCheckConfig {
    /// Validates the health-check settings; `api` names the owning
    /// definition in errors.
    fn validate(&self, api: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        if !self.path.starts_with('/') {
            return Err(fail(format!(
                "`health_check.path` must start with '/', got `{}`",
                self.path
            )));
        }
        if self.path.parse::<http::uri::PathAndQuery>().is_err() {
            return Err(fail(format!(
                "`health_check.path` is not a valid URL path: `{}`",
                self.path
            )));
        }
        if self.interval_ms == 0 {
            return Err(fail(
                "`health_check.interval_ms` must be greater than zero".into(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(fail(
                "`health_check.timeout_ms` must be greater than zero".into(),
            ));
        }
        if self.unhealthy_threshold == 0 {
            return Err(fail(
                "`health_check.unhealthy_threshold` must be greater than zero".into(),
            ));
        }
        if self.healthy_threshold == 0 {
            return Err(fail(
                "`health_check.healthy_threshold` must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

fn default_discovery_interval_ms() -> u64 {
    10_000
}

fn default_discovery_timeout_ms() -> u64 {
    5_000
}

/// Scheme applied to discovered `host[:port]` entries when a definition does
/// not set `service_discovery.scheme`.
pub const DEFAULT_DISCOVERY_SCHEME: &str = "http";

fn default_discovery_scheme() -> String {
    DEFAULT_DISCOVERY_SCHEME.to_owned()
}

/// Upstream service discovery via HTTP+JSON polling (see
/// [`ApiDefinition::service_discovery`]).
///
/// Each gateway pod polls `endpoint` every `interval_ms` and extracts the
/// current upstream addresses from the JSON response using the configured
/// data paths (see [`Self::extract_entries`] for the exact semantics — the
/// mechanism covers Consul/etcd/Eureka-style REST catalogs with one shape).
/// A successful poll that yields a *different* address list replaces the
/// API's load-balancing targets live, without a reload.
///
/// Until the first successful poll the API forwards to its static seeds
/// (`target_list`, else `target_url` — which stays required as the
/// canonical fallback). A failed poll — fetch error, non-2xx, unparseable
/// body, extraction error, invalid entry, or an *empty* result — keeps the
/// previous addresses and logs a warning: stale targets beat empty targets,
/// so discovery can never leave an API with nothing to forward to.
///
/// Polling is pod-local (each pod polls the endpoint itself, like health
/// probing); the discovery endpoint is fetched over HTTP/1.1 regardless of
/// the API's `upstream_http2` setting, and response bodies are capped at
/// 1 MiB.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    /// The URL polled for the current upstream addresses. Must be an
    /// absolute `http`/`https` URL.
    pub endpoint: String,

    /// Dotted path to the host entry (or list of host entries) inside the
    /// JSON response — e.g. `"Address"` or `"node.ip"`. Segments index
    /// object keys, or array elements when they parse as a number. Empty
    /// (the default) means the looked-up value itself.
    #[serde(default)]
    pub data_path: String,

    /// Optional dotted path to the port for each host entry. The value must
    /// be an integer `1`–`65535` or a string of digits. Unset = discovered
    /// entries carry their own port or use the scheme default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_data_path: Option<String>,

    /// Optional dotted path to a JSON *array* to iterate: per element,
    /// [`Self::data_path`] and [`Self::port_data_path`] are resolved
    /// relative to the element instead of the response root. Empty means
    /// the response root itself is the array (e.g. Consul's
    /// `/v1/catalog/service/{name}`). Unset = no iteration; the paths
    /// resolve from the root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_data_path: Option<String>,

    /// Scheme (`http` or `https`) applied to discovered `host[:port]`
    /// entries. Defaults to [`DEFAULT_DISCOVERY_SCHEME`]. Entries that are
    /// already full `http(s)://` URLs keep their own scheme.
    #[serde(default = "default_discovery_scheme")]
    pub scheme: String,

    /// Milliseconds between polls (per pod). Defaults to `10000`.
    #[serde(default = "default_discovery_interval_ms")]
    pub interval_ms: u64,

    /// Milliseconds a poll may take before counting as a failure.
    /// Defaults to `5000`.
    #[serde(default = "default_discovery_timeout_ms")]
    pub timeout_ms: u64,
}

/// One host entry extracted from a discovery response by
/// [`ServiceDiscoveryConfig::extract_entries`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredEntry {
    /// The raw host entry: a bare host, `host:port` authority, or a full
    /// `http(s)://` URL.
    pub host: String,
    /// Port resolved via `port_data_path`, if configured.
    pub port: Option<u16>,
}

/// Resolves a dotted path inside a JSON value: object segments index keys,
/// and a segment that parses as a number indexes an array element. The empty
/// path resolves to the value itself.
fn json_lookup<'a>(mut value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    if path.is_empty() {
        return Some(value);
    }
    for segment in path.split('.') {
        value = match value {
            serde_json::Value::Object(map) => map.get(segment)?,
            serde_json::Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(value)
}

/// Coerces a looked-up port value: an integer `1`–`65535`, or a string of
/// digits in that range. `path` names the offending path in errors.
fn coerce_port(value: &serde_json::Value, path: &str) -> Result<u16, String> {
    let port = match value {
        serde_json::Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        serde_json::Value::String(s) if s.chars().all(|c| c.is_ascii_digit()) => {
            s.parse::<u16>().ok()
        }
        _ => None,
    };
    match port {
        Some(p) if p != 0 => Ok(p),
        _ => Err(format!(
            "`port_data_path` `{path}` must be a port between 1 and 65535, got `{value}`"
        )),
    }
}

/// Checks dotted-path syntax: the empty path is allowed (identity), but a
/// non-empty path must have no empty segments (`a..b`, `.a`, `a.`).
fn check_data_path(path: &str) -> Result<(), String> {
    if !path.is_empty() && path.split('.').any(str::is_empty) {
        return Err(format!("has an empty segment: `{path}`"));
    }
    Ok(())
}

impl ServiceDiscoveryConfig {
    /// Validates the discovery settings; `api` names the owning definition
    /// in errors.
    fn validate(&self, api: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        if let Err(reason) = check_target_url(&self.endpoint) {
            return Err(fail(format!("`service_discovery.endpoint` {reason}")));
        }
        if self.scheme != "http" && self.scheme != "https" {
            return Err(fail(format!(
                "`service_discovery.scheme` must be `http` or `https`, got `{}`",
                self.scheme
            )));
        }
        if self.interval_ms == 0 {
            return Err(fail(
                "`service_discovery.interval_ms` must be greater than zero".into(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(fail(
                "`service_discovery.timeout_ms` must be greater than zero".into(),
            ));
        }
        for (name, path) in [
            ("data_path", Some(&self.data_path)),
            ("port_data_path", self.port_data_path.as_ref()),
            ("parent_data_path", self.parent_data_path.as_ref()),
        ] {
            if let Some(path) = path {
                if let Err(reason) = check_data_path(path) {
                    return Err(fail(format!("`service_discovery.{name}` {reason}")));
                }
            }
        }
        Ok(())
    }

    /// Extracts the host entries from a discovery response document.
    ///
    /// With [`Self::parent_data_path`] set, that path must resolve to an
    /// array; for each element, [`Self::data_path`] must resolve to a JSON
    /// string (the host entry) and [`Self::port_data_path`], when set, to a
    /// valid port. Without it, `data_path` resolves from the root to either
    /// a single string or an array of strings, and `port_data_path`
    /// resolves from the root to one port applied to every entry.
    ///
    /// # Errors
    ///
    /// Any failed lookup or malformed value fails the whole extraction with
    /// a descriptive message — never a partial list, so a broken discovery
    /// response cannot silently shrink the upstream pool.
    pub fn extract_entries(&self, doc: &serde_json::Value) -> Result<Vec<DiscoveredEntry>, String> {
        if let Some(parent_path) = &self.parent_data_path {
            let parent = json_lookup(doc, parent_path).ok_or_else(|| {
                format!("`parent_data_path` `{parent_path}` not found in the response")
            })?;
            let items = parent
                .as_array()
                .ok_or_else(|| format!("`parent_data_path` `{parent_path}` is not an array"))?;
            items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let host = self.entry_host(item, &format!("[{index}]"))?;
                    let port = self
                        .port_data_path
                        .as_ref()
                        .map(|path| {
                            json_lookup(item, path)
                                .ok_or_else(|| {
                                    format!(
                                        "`port_data_path` `{path}` not found in element [{index}]"
                                    )
                                })
                                .and_then(|value| coerce_port(value, path))
                        })
                        .transpose()?;
                    Ok(DiscoveredEntry { host, port })
                })
                .collect()
        } else {
            let value = json_lookup(doc, &self.data_path).ok_or_else(|| {
                format!("`data_path` `{}` not found in the response", self.data_path)
            })?;
            let hosts = match value {
                serde_json::Value::String(host) if !host.trim().is_empty() => {
                    vec![host.clone()]
                }
                serde_json::Value::String(_) => {
                    return Err(format!(
                        "`data_path` `{}` is not a non-empty string",
                        self.data_path
                    ));
                }
                serde_json::Value::Array(items) => items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| match item.as_str() {
                        Some(host) if !host.trim().is_empty() => Ok(host.to_owned()),
                        _ => Err(format!(
                            "`data_path` `{}` element [{index}] is not a non-empty string",
                            self.data_path
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => {
                    return Err(format!(
                        "`data_path` `{}` must resolve to a string or array of strings",
                        self.data_path
                    ));
                }
            };
            let port = self
                .port_data_path
                .as_ref()
                .map(|path| {
                    json_lookup(doc, path)
                        .ok_or_else(|| {
                            format!("`port_data_path` `{path}` not found in the response")
                        })
                        .and_then(|value| coerce_port(value, path))
                })
                .transpose()?;
            Ok(hosts
                .into_iter()
                .map(|host| DiscoveredEntry { host, port })
                .collect())
        }
    }

    /// Resolves [`Self::data_path`] inside `scope` to a non-empty string
    /// host entry; `place` names the scope in errors.
    fn entry_host(&self, scope: &serde_json::Value, place: &str) -> Result<String, String> {
        let value = json_lookup(scope, &self.data_path)
            .ok_or_else(|| format!("`data_path` `{}` not found in {place}", self.data_path))?;
        match value.as_str() {
            Some(host) if !host.trim().is_empty() => Ok(host.to_owned()),
            _ => Err(format!(
                "`data_path` `{}` in {place} is not a non-empty string",
                self.data_path
            )),
        }
    }
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_breaker_cooldown_ms() -> u64 {
    30_000
}

/// Per-route circuit breaking on live traffic (see
/// [`ApiDefinition::circuit_breaker`]).
///
/// Each gateway pod counts consecutive upstream failures — transport errors,
/// upstream timeouts, and `5xx` upstream responses — for the route. After
/// `failure_threshold` consecutive failures the circuit *opens*: requests are
/// rejected with `503` without contacting the upstream for `cooldown_ms`.
/// The first request after the cooldown is let through as a trial
/// (*half-open*): its success closes the circuit, its failure re-opens it
/// for another cooldown. Any upstream success resets the failure count.
///
/// A deliberate design choice: rather than a rate-based breaker
/// (`threshold_percent` over `samples`, per endpoint), this one counts
/// consecutive failures per route, which needs no sliding sample window and
/// stays lock-free on the hot path. State is pod-local, like load-balancing
/// rotation and health eviction.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Consecutive upstream failures after which the circuit opens.
    /// Defaults to `5`.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Milliseconds the circuit stays open before a trial request is let
    /// through. Defaults to `30000`.
    #[serde(default = "default_breaker_cooldown_ms")]
    pub cooldown_ms: u64,
}

impl CircuitBreakerConfig {
    /// Validates the breaker settings; `api` names the owning definition in
    /// errors.
    fn validate(&self, api: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        if self.failure_threshold == 0 {
            return Err(fail(
                "`circuit_breaker.failure_threshold` must be greater than zero".into(),
            ));
        }
        if self.cooldown_ms == 0 {
            return Err(fail(
                "`circuit_breaker.cooldown_ms` must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

fn default_cache_ttl_secs() -> u64 {
    60
}

/// Default cap on cacheable response bodies: 1 MiB.
const DEFAULT_CACHE_MAX_BODY_BYTES: u64 = 1_048_576;

fn default_cache_max_body_bytes() -> u64 {
    DEFAULT_CACHE_MAX_BODY_BYTES
}

/// Response caching for one API (see [`ApiDefinition::cache`]).
///
/// The gateway caches upstream responses in storage (shared by every pod)
/// under [`response_cache_key_prefix`] and answers repeat requests without
/// contacting the upstream, marking them with an `x-g2-cache: hit` header.
///
/// What is cached is deliberately conservative:
///
/// - **Safe methods only** (`GET`, `HEAD`, `OPTIONS`). Each method
///   caches separately.
/// - **`2xx` responses only**, and never a response carrying `Set-Cookie`:
///   the cache is shared across clients and keys, so a
///   per-client response must never be replayed to someone else.
/// - Bodies larger than `max_body_bytes` are passed through uncached.
///
/// Entries are keyed by the exact request method, path, and query (no
/// normalization: `?a=1&b=2` and `?b=2&a=1` cache separately) and expire
/// after `ttl_secs`. HTTP cache-control semantics (`Vary`, `no-store`,
/// `Age`) are not interpreted — the TTL is the whole contract.
///
/// GraphQL traffic (`POST`) is never cached here; `graphql.cache` reuses
/// this config shape for operation-keyed caching instead (ADR-0012).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Seconds a cached response is served before it expires. Defaults to
    /// `60`.
    #[serde(default = "default_cache_ttl_secs")]
    pub ttl_secs: u64,

    /// Largest response body (in bytes) worth caching; bigger responses are
    /// streamed through uncached. Defaults to 1 MiB.
    #[serde(default = "default_cache_max_body_bytes")]
    pub max_body_bytes: u64,
}

impl CacheConfig {
    /// Validates the cache settings; `api` names the owning definition in
    /// errors and `field_prefix` names the config field holding this block
    /// (`cache` or `graphql.cache`).
    pub(crate) fn validate(&self, api: &str, field_prefix: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };
        if self.ttl_secs == 0 {
            return Err(fail(format!(
                "`{field_prefix}.ttl_secs` must be greater than zero"
            )));
        }
        if self.max_body_bytes == 0 {
            return Err(fail(format!(
                "`{field_prefix}.max_body_bytes` must be greater than zero"
            )));
        }
        Ok(())
    }
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

/// HMAC digest algorithms supported by [`AuthConfig::Hmac`].
///
/// Serialized with the draft-cavage wire names (`hmac-sha256`, …), which are
/// also what the `Signature` header's `algorithm` parameter carries.
/// `hmac-sha1` is deliberately unsupported (a hardening choice).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HmacAlgorithm {
    /// HMAC over SHA-256 (`hmac-sha256`).
    HmacSha256,
    /// HMAC over SHA-384 (`hmac-sha384`).
    HmacSha384,
    /// HMAC over SHA-512 (`hmac-sha512`).
    HmacSha512,
}

impl HmacAlgorithm {
    /// The draft-cavage algorithm name (`"hmac-sha256"`, …) — the serialized
    /// form, for matching a `Signature` header's `algorithm` parameter
    /// without allocating.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
        }
    }
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
    /// key (or a key fetched from `jwks_url`) and its claims are turned into
    /// an ephemeral session (no storage lookup).
    Jwt {
        /// Signature algorithm the tokens must use.
        signing_method: JwtSigningMethod,

        /// Shared secret for [`JwtSigningMethod::Hs256`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<String>,

        /// PEM-encoded RSA public key for [`JwtSigningMethod::Rs256`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key_pem: Option<String>,

        /// URL of a JWKS document (RFC 7517 key set) to fetch RS256
        /// verification keys from; tokens must carry a `kid` matching a key
        /// in the set. Mutually exclusive with `public_key_pem`; rs256 only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jwks_url: Option<String>,

        /// Seconds between background JWKS re-fetches. Defaults to
        /// [`DEFAULT_JWKS_REFRESH_SECS`]; only valid alongside `jwks_url`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jwks_refresh_secs: Option<u64>,

        /// Request header carrying the JWT (a `Bearer ` prefix is stripped).
        #[serde(default = "default_auth_header")]
        header: String,

        /// Claim used as the caller identity (session alias and rate-limit
        /// key). Defaults to `sub`.
        #[serde(default = "default_identity_claim")]
        identity_claim: String,
    },

    /// OIDC bearer auth: RS256 tokens issued by an external identity
    /// provider are verified against keys discovered from `issuer_url`
    /// (or fetched directly from `jwks_url`), with exact `iss` and `aud`
    /// checks, and their claims are turned into an ephemeral session.
    ///
    /// Optionally maps the OAuth2 client id (read from `policy_claim`) to a
    /// stored [`Policy`](crate::Policy) via `policy_map`.
    Oidc {
        /// Identity provider issuer URL. Matched **byte-for-byte** against
        /// the token's `iss` claim (a trailing-slash mismatch fails
        /// closed, per OIDC), and used as the base of the discovery URL
        /// `{issuer_url}/.well-known/openid-configuration` (one trailing
        /// `/` is trimmed before concatenation only).
        issuer_url: String,

        /// Accepted `aud` values; required and non-empty (a deliberate
        /// hardening choice). A token passes if its `aud`
        /// intersects this list.
        audiences: Vec<String>,

        /// Direct JWKS URL, skipping OIDC discovery — for providers whose
        /// discovery document is absent or non-standard.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jwks_url: Option<String>,

        /// Seconds between background JWKS re-fetches. Defaults to
        /// [`DEFAULT_JWKS_REFRESH_SECS`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jwks_refresh_secs: Option<u64>,

        /// Request header carrying the token (a `Bearer ` prefix is
        /// stripped).
        #[serde(default = "default_auth_header")]
        header: String,

        /// Claim used as the caller identity (session alias and rate-limit
        /// key). Defaults to `sub`.
        #[serde(default = "default_identity_claim")]
        identity_claim: String,

        /// Claim holding the OAuth2 client id used for policy mapping.
        /// Defaults to [`DEFAULT_OIDC_POLICY_CLAIM`] (`azp`); RFC 9068
        /// access tokens may want `client_id` instead. (A single
        /// configurable claim, not `aud`/`azp` heuristics.)
        #[serde(default = "default_oidc_policy_claim")]
        policy_claim: String,

        /// Client id → policy id. When non-empty, a token whose client id
        /// is not mapped is rejected (deny-unmatched); when
        /// empty (the default), tokens get a JWT-like ephemeral session
        /// with access to this API only.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        policy_map: BTreeMap<String, String>,
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

    /// Mutual-TLS auth: the client certificate the TLS handshake verified
    /// is the credential.
    ///
    /// The certificate's SHA-256 fingerprint (see
    /// [`session::cert_fingerprint_hex`](crate::session::cert_fingerprint_hex))
    /// resolves — hashed, under an `mtls:` namespace — to a stored
    /// [`KeySession`](crate::KeySession), provisioned via the admin key
    /// CRUD as the raw key `mtls:{fingerprint}`. A certificate the CA
    /// signed but nobody provisioned is rejected: transport-level
    /// verification (the gateway's `tls.client_cert_mode`) and per-API
    /// authorization are separate layers. Requires the gateway to
    /// terminate TLS with `client_cert_mode: optional` or `required`; see
    /// `docs/tls.md`.
    Mtls {},

    /// HMAC request-signature auth (draft-cavage HTTP Signatures):
    /// `Authorization: Signature keyId="…",algorithm="hmac-sha256",
    /// headers="(request-target) date",signature="…"`.
    ///
    /// The `keyId` resolves (hashed, under an `hmac:` namespace) to a stored
    /// [`KeySession`](crate::KeySession) whose
    /// [`hmac`](crate::session::HmacData) data carries the shared secret the
    /// signature is verified with; provisioning is the admin key CRUD with
    /// the raw key `hmac:{keyId}`. Credentials are read from the
    /// `Authorization` header only (where the `Signature` scheme lives).
    Hmac {
        /// Algorithms accepted from the `Signature` header. Defaults to all
        /// three SHA-2 variants; `hmac-sha1` is deliberately unsupported.
        #[serde(default = "default_hmac_algorithms")]
        allowed_algorithms: Vec<HmacAlgorithm>,

        /// Maximum seconds the request's `Date` header may differ from the
        /// gateway clock. Defaults to [`DEFAULT_HMAC_CLOCK_SKEW_SECS`]; an
        /// explicit `null` disables the check. While enabled, `date` must be
        /// among the signed headers (an unsigned `Date` is
        /// attacker-controlled, so a skew check on it would prove nothing).
        ///
        /// Never skip-serialized: `null` is a meaningful third state
        /// (disabled), distinct from absent (default 300).
        #[serde(default = "default_hmac_clock_skew")]
        allowed_clock_skew_secs: Option<u64>,
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
            Self::Oidc { .. } => "oidc",
            Self::BasicAuth { .. } => "basic_auth",
            Self::Mtls {} => "mtls",
            Self::Hmac { .. } => "hmac",
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
                jwks_url,
                jwks_refresh_secs,
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
                if jwks_refresh_secs.is_some() && jwks_url.is_none() {
                    return Err(fail(
                        "`auth.jwks_refresh_secs` requires `auth.jwks_url`".into(),
                    ));
                }
                if jwks_refresh_secs.is_some_and(|s| s == 0) {
                    return Err(fail("`auth.jwks_refresh_secs` must be at least 1".into()));
                }
                if let Some(url) = jwks_url {
                    let uri = url.parse::<http::Uri>().ok().filter(|u| {
                        matches!(u.scheme_str(), Some("http" | "https")) && u.authority().is_some()
                    });
                    if uri.is_none() {
                        return Err(fail(format!(
                            "`auth.jwks_url` is not a valid http(s) URL: `{url}`"
                        )));
                    }
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
                        if jwks_url.is_some() {
                            return Err(fail(
                                "`auth.jwks_url` is not used with hs256; remove it".into(),
                            ));
                        }
                    }
                    JwtSigningMethod::Rs256 => {
                        let has_pem = public_key_pem
                            .as_deref()
                            .is_some_and(|s| !s.trim().is_empty());
                        let has_jwks = jwks_url.as_deref().is_some_and(|s| !s.trim().is_empty());
                        if has_pem == has_jwks {
                            return Err(fail(
                                "rs256 requires exactly one of `auth.public_key_pem` or \
                                 `auth.jwks_url`"
                                    .into(),
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
            Self::Oidc {
                issuer_url,
                audiences,
                jwks_url,
                jwks_refresh_secs,
                header,
                identity_claim,
                policy_claim,
                policy_map,
            } => {
                if http::header::HeaderName::from_bytes(header.as_bytes()).is_err() {
                    return Err(fail(format!(
                        "`auth.header` is not a valid header name: `{header}`"
                    )));
                }
                if identity_claim.trim().is_empty() {
                    return Err(fail("`auth.identity_claim` must not be empty".into()));
                }
                if policy_claim.trim().is_empty() {
                    return Err(fail("`auth.policy_claim` must not be empty".into()));
                }
                // The issuer doubles as the discovery base URL, so it must
                // be a plain http(s) origin+path — query or fragment parts
                // would corrupt the `/.well-known/…` concatenation.
                let issuer_ok = issuer_url.parse::<Uri>().ok().is_some_and(|u| {
                    matches!(u.scheme_str(), Some("http" | "https"))
                        && u.authority().is_some()
                        && u.query().is_none()
                }) && !issuer_url.contains('#');
                if !issuer_ok {
                    return Err(fail(format!(
                        "`auth.issuer_url` is not a valid http(s) URL without \
                         query or fragment: `{issuer_url}`"
                    )));
                }
                // Verifying tokens without an audience check would accept
                // any token the IdP ever issued for any consumer; jsonweb-
                // token's Validation also rejects aud-bearing tokens when
                // no audience is configured. Require one, always.
                if audiences.is_empty() {
                    return Err(fail("`auth.audiences` must not be empty".into()));
                }
                if audiences.iter().any(|a| a.trim().is_empty()) {
                    return Err(fail("`auth.audiences` entries must not be empty".into()));
                }
                if let Some(url) = jwks_url {
                    let uri = url.parse::<Uri>().ok().filter(|u| {
                        matches!(u.scheme_str(), Some("http" | "https")) && u.authority().is_some()
                    });
                    if uri.is_none() {
                        return Err(fail(format!(
                            "`auth.jwks_url` is not a valid http(s) URL: `{url}`"
                        )));
                    }
                }
                if jwks_refresh_secs.is_some_and(|s| s == 0) {
                    return Err(fail("`auth.jwks_refresh_secs` must be at least 1".into()));
                }
                if policy_map
                    .iter()
                    .any(|(k, v)| k.trim().is_empty() || v.trim().is_empty())
                {
                    return Err(fail(
                        "`auth.policy_map` keys and values must not be empty".into(),
                    ));
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
            // Whether the listener actually terminates TLS with client
            // certs enabled is process-level config the definition cannot
            // see; the auth layer rejects at request time instead.
            Self::Mtls {} => Ok(()),
            Self::Hmac {
                allowed_algorithms,
                allowed_clock_skew_secs,
            } => {
                if allowed_algorithms.is_empty() {
                    return Err(fail("`auth.allowed_algorithms` must not be empty".into()));
                }
                let mut seen = allowed_algorithms.clone();
                seen.sort_unstable_by_key(|a| a.as_str());
                seen.dedup();
                if seen.len() != allowed_algorithms.len() {
                    return Err(fail(
                        "`auth.allowed_algorithms` must not repeat entries".into(),
                    ));
                }
                if *allowed_clock_skew_secs == Some(0) {
                    return Err(fail(
                        "`auth.allowed_clock_skew_secs` must be at least 1 \
                         (use null to disable the Date check)"
                            .into(),
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

    /// Upstream base URLs for round-robin load balancing. When non-empty,
    /// upstream requests rotate across these
    /// URLs — each gateway pod keeps its own rotation — and [`Self::target_url`]
    /// is not used for forwarding. Every entry follows `target_url`'s rules
    /// and may carry its own base path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_list: Vec<String>,

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

    /// Optional minijinja body transforms for matching request and response
    /// bodies (see [`BodyTransforms`]). Matching bodies are buffered whole —
    /// requests up to [`max_request_body_bytes`](Self::max_request_body_bytes)
    /// (else 1 MiB, over → `413`), responses up to the block's
    /// `max_response_body_bytes` (over → `502`) — and transforms fail closed:
    /// a failing render answers `500` (request) or `502` (response) rather
    /// than passing the original body through. Templates see JSON-parsed
    /// bodies only (`body` is `none` for non-JSON payloads; `raw` always
    /// carries the text). Design: ADR-0007.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform_body: Option<BodyTransforms>,

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
    /// it session rate limiting, which needs a session) — e.g. a public
    /// health or webhook endpoint on an otherwise protected API. API-level
    /// [`endpoint_rate_limits`](Self::endpoint_rate_limits) still apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_auth_paths: Vec<PathRule>,

    /// Mock-response rules, tried in order after auth and rate limiting;
    /// the first match is answered by the gateway without contacting the
    /// upstream (see [`MockResponse`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mock_responses: Vec<MockResponse>,

    /// Aggregate per-endpoint rate limits: the first rule matching a
    /// request caps how many matching requests **all clients combined** may
    /// make per window; excess is rejected with `429`. Counted
    /// independently of any key session's rate/quota and enforced even on
    /// keyless APIs and `ignore_auth_paths` matches (see
    /// [`EndpointRateLimit`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoint_rate_limits: Vec<EndpointRateLimit>,

    /// Optional CORS settings: when present the gateway answers preflight
    /// requests and decorates responses with `Access-Control-*` headers
    /// (see [`CorsConfig`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors: Option<CorsConfig>,

    /// When non-empty, only clients whose socket address matches one of
    /// these IPs/CIDR networks may use this API; everyone else gets `403`.
    /// The peer address is used, never client-supplied headers like
    /// `X-Forwarded-For` (which are spoofable).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_ips: Vec<String>,

    /// Clients whose socket address matches one of these IPs/CIDR networks
    /// are rejected with `403`. A block always wins over `allow_ips`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_ips: Vec<String>,

    /// Maximum request body size in bytes; larger requests are rejected
    /// with `413`. Enforced on the `Content-Length` header and, for
    /// chunked/streamed bodies, on the actual bytes read. Unset = no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_request_body_bytes: Option<u64>,

    /// Optional active upstream health checking: each pod probes every
    /// upstream address on an interval and evicts failing addresses from the
    /// load-balancing rotation until they recover (see
    /// [`HealthCheckConfig`]). Unset = no probing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,

    /// Optional upstream service discovery: each pod polls an HTTP+JSON
    /// endpoint on an interval and live-swaps the API's load-balancing
    /// targets to the discovered addresses (see [`ServiceDiscoveryConfig`]).
    /// [`Self::target_list`]/[`Self::target_url`] remain the seed addresses
    /// used until the first successful poll. Unset = static targets only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_discovery: Option<ServiceDiscoveryConfig>,

    /// Optional per-route circuit breaking: after enough consecutive
    /// upstream failures on live traffic, requests are answered `503`
    /// without contacting the upstream until a cooldown trial succeeds (see
    /// [`CircuitBreakerConfig`]). Unset = no breaking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Additional forwarding attempts after an upstream transport failure
    /// (connection refused/reset — not timeouts or `5xx` responses), at most
    /// `10`. Each attempt picks the next load-balancing address. Only
    /// requests that can be safely replayed are retried: idempotent methods
    /// (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`, `TRACE`, after any method
    /// transform) whose body is empty — a streamed request body cannot be
    /// re-sent. All attempts share the API's one `upstream_timeout_ms`
    /// budget. Defaults to `0` (no retries).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub upstream_retries: u32,

    /// When `true`, HTTP/1.1 `Connection: Upgrade` requests (WebSocket being
    /// the common protocol) are passed through: the upgrade headers are
    /// forwarded, and when the upstream answers `101 Switching Protocols` the
    /// gateway tunnels the connection's raw bytes in both directions for its
    /// remaining lifetime. The upgrade *request* still runs the full
    /// middleware chain (auth, rate limits, path lists), but bytes inside an
    /// established tunnel are opaque to the gateway. When `false` (the
    /// default) the upgrade headers are stripped like any other hop-by-hop
    /// header and the request is proxied as plain HTTP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enable_upgrades: bool,

    /// When `true`, every upstream request for this API is sent over
    /// HTTP/2: plaintext `http://` targets speak h2c (prior knowledge —
    /// the upstream must accept HTTP/2 directly, there is no HTTP/1.1
    /// fallback), and `https://` targets offer only `h2` via ALPN. This is
    /// what makes gRPC passthrough work end to end (response trailers such
    /// as `grpc-status` are forwarded), but it applies to *all* the API's
    /// upstream traffic, gRPC or not. Cannot be combined with
    /// [`Self::enable_upgrades`]: an HTTP/1.1 `Connection: Upgrade` cannot
    /// cross an HTTP/2-only upstream connection. When `false` (the
    /// default) upstream requests are HTTP/1.1.
    #[serde(default, skip_serializing_if = "is_false")]
    pub upstream_http2: bool,

    /// Optional response caching: safe-method (`GET`/`HEAD`/`OPTIONS`) `2xx`
    /// upstream responses are stored in shared storage for a per-API TTL and
    /// replayed without contacting the upstream (see [`CacheConfig`]).
    /// Unset = no caching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheConfig>,

    /// Optional API versioning: the request header or query parameter that
    /// selects a version, and per-version overrides applied on top of this
    /// definition (see [`VersioningConfig`]). Unset = unversioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versioning: Option<VersioningConfig>,

    /// Optional GraphQL settings: present, the API is treated as a GraphQL
    /// API — requests are parsed, validated against the configured schema,
    /// and policed (depth limits, introspection control, per-key field
    /// permissions) before being proxied (see [`GraphQlConfig`]).
    /// Unset = plain HTTP proxying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphql: Option<GraphQlConfig>,

    /// Optional WASM plugin hooks: guest modules run before authentication
    /// (`pre`) and after authentication/rate limiting (`post`), able to
    /// mutate request headers or answer the request themselves (see
    /// [`PluginsConfig`]). Unset = no plugins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugins: Option<PluginsConfig>,
}

/// Serde helper: keeps default-zero counters off the wire.
#[expect(clippy::trivially_copy_pass_by_ref, reason = "serde requires &T")]
fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Serde helper: keeps default-off flags off the wire.
#[expect(clippy::trivially_copy_pass_by_ref, reason = "serde requires &T")]
fn is_false(b: &bool) -> bool {
    !*b
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

/// Prefix shared by every cached response of one cache scope:
/// `g2:{org_id}:cache:{scope}:`.
///
/// `scope` is the API id for an unversioned API, or `{api_id}:{version}` for
/// one version of a versioned API — versions can differ in upstream and
/// transforms, so they must never share entries. The GraphQL-aware cache
/// (`graphql.cache`) uses `{scope}:graphql`, keeping its entries disjoint
/// from the HTTP cache's. The full entry key is this prefix plus a digest of
/// the request (method, path, and query for the HTTP cache; schema hash,
/// operation name, query text, and variables for the GraphQL cache); scoping
/// by prefix keeps a future flush-by-API admin operation a plain prefix scan.
#[must_use]
pub fn response_cache_key_prefix(org_id: &str, scope: &str) -> String {
    format!("g2:{org_id}:cache:{scope}:")
}

/// Checks that a target URL is an absolute `http`/`https` URL with a host;
/// the error is a reason fragment the caller prefixes with the field name.
fn check_target_url(url: &str) -> Result<(), String> {
    let uri: Uri = url
        .parse()
        .map_err(|e| format!("is not a valid URL: {e}"))?;
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        other => {
            return Err(format!(
                "must use http or https, got `{}`",
                other.unwrap_or("<none>")
            ));
        }
    }
    if uri.authority().is_none() {
        return Err("must include a host".into());
    }
    Ok(())
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

        if let Err(reason) = check_target_url(&self.target_url) {
            return Err(fail(format!("`target_url` {reason}")));
        }
        for (index, url) in self.target_list.iter().enumerate() {
            if let Err(reason) = check_target_url(url) {
                return Err(fail(format!("`target_list[{index}]` {reason}")));
            }
        }
        self.auth.validate(&self.api_id)?;
        if let Some(transforms) = &self.transform_headers {
            transforms.validate(&self.api_id)?;
        }
        if let Some(transforms) = &self.transform_body {
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
        for (index, rule) in self.endpoint_rate_limits.iter().enumerate() {
            rule.validate(&self.api_id, index)?;
        }
        if let Some(cors) = &self.cors {
            cors.validate(&self.api_id)?;
        }
        security::validate_ip_list(&self.allow_ips, &self.api_id, "allow_ips")?;
        security::validate_ip_list(&self.block_ips, &self.api_id, "block_ips")?;
        if self.max_request_body_bytes == Some(0) {
            return Err(fail(
                "`max_request_body_bytes` must be greater than zero (omit it for no limit)".into(),
            ));
        }
        if let Some(health) = &self.health_check {
            health.validate(&self.api_id)?;
        }
        if let Some(discovery) = &self.service_discovery {
            discovery.validate(&self.api_id)?;
        }
        if let Some(breaker) = &self.circuit_breaker {
            breaker.validate(&self.api_id)?;
        }
        if self.upstream_retries > 10 {
            return Err(fail(format!(
                "`upstream_retries` must be at most 10, got {}",
                self.upstream_retries
            )));
        }
        if self.upstream_http2 && self.enable_upgrades {
            return Err(fail(
                "`upstream_http2` cannot be combined with `enable_upgrades`: an HTTP/1.1 \
                 `Connection: Upgrade` cannot cross an HTTP/2-only upstream connection"
                    .into(),
            ));
        }
        if self.upstream_http2 && self.graphql_subscriptions_enabled() {
            return Err(fail(
                "`upstream_http2` cannot be combined with `graphql.subscriptions`: the \
                 subscription WebSocket upgrade cannot cross an HTTP/2-only upstream \
                 connection"
                    .into(),
            ));
        }
        if let Some(cache) = &self.cache {
            cache.validate(&self.api_id, "cache")?;
        }
        if let Some(graphql) = &self.graphql {
            graphql.validate(&self.api_id)?;
        }
        if let Some(plugins) = &self.plugins {
            plugins.validate(&self.api_id)?;
        }
        // Last, so per-version effective definitions are validated only
        // after the base fields have passed (errors then name the version).
        if let Some(versioning) = &self.versioning {
            versioning.validate(self)?;
        }
        Ok(())
    }

    /// Whether GraphQL subscriptions over WebSocket are enabled for this
    /// API: a [`graphql`](Self::graphql) block that is enabled and carries
    /// an enabled `subscriptions` block. Implies upgrade capability on the
    /// forwarding path even when [`enable_upgrades`](Self::enable_upgrades)
    /// is off — the GraphQL layer polices or rejects every WebSocket
    /// handshake on such an API, so no opaque tunnel can result (ADR-0009).
    #[must_use]
    pub fn graphql_subscriptions_enabled(&self) -> bool {
        self.graphql
            .as_ref()
            .is_some_and(|g| g.enabled && g.subscriptions.as_ref().is_some_and(|s| s.enabled))
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
    fn transform_body_is_validated() {
        let mut def = parse(minimal_json());
        def.transform_body = Some(
            serde_json::from_str(r#"{"request": [{"pattern": "^/x$", "template": "{{ raw }}"}]}"#)
                .expect("parses"),
        );
        def.validate().expect("valid transform_body");

        def.transform_body = Some(
            serde_json::from_str(
                r#"{"request": [{"pattern": "^/x$", "template": "{{ unclosed"}]}"#,
            )
            .expect("parses"),
        );
        let err = def.validate().unwrap_err().to_string();
        assert!(err.contains("transform_body.request[0]"), "got: {err}");
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
    fn mtls_mode_parses_and_round_trips() {
        let json = r#"{
            "api_id": "certs-only",
            "name": "mTLS API",
            "listen_path": "/m/",
            "target_url": "http://m.internal",
            "auth": { "mode": "mtls" }
        }"#;
        let def = parse(json);
        assert_eq!(def.auth, AuthConfig::Mtls {});
        assert_eq!(def.auth.mode_name(), "mtls");
        def.validate().expect("mtls definition is valid");
        // The serialized tag round-trips.
        let out = serde_json::to_string(&def.auth).expect("serialize");
        assert_eq!(out, r#"{"mode":"mtls"}"#);
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
            jwks_url: None,
            jwks_refresh_secs: None,
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        def.validate().expect("hs256 with secret is valid");

        // hs256 without a secret / with a stray PEM: invalid.
        def.auth = AuthConfig::Jwt {
            signing_method: JwtSigningMethod::Hs256,
            secret: None,
            public_key_pem: None,
            jwks_url: None,
            jwks_refresh_secs: None,
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        assert!(def.validate().is_err());
        def.auth = AuthConfig::Jwt {
            signing_method: JwtSigningMethod::Hs256,
            secret: Some("shhh".into()),
            public_key_pem: Some("-----BEGIN PUBLIC KEY-----".into()),
            jwks_url: None,
            jwks_refresh_secs: None,
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        assert!(def.validate().is_err());

        // rs256 requires a PEM and no secret.
        def.auth = AuthConfig::Jwt {
            signing_method: JwtSigningMethod::Rs256,
            secret: None,
            public_key_pem: Some("-----BEGIN PUBLIC KEY-----".into()),
            jwks_url: None,
            jwks_refresh_secs: None,
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        def.validate().expect("rs256 with pem is valid");
        def.auth = AuthConfig::Jwt {
            signing_method: JwtSigningMethod::Rs256,
            secret: Some("shhh".into()),
            public_key_pem: Some("-----BEGIN PUBLIC KEY-----".into()),
            jwks_url: None,
            jwks_refresh_secs: None,
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };
        assert!(def.validate().is_err());
    }

    #[test]
    fn jwt_auth_validates_jwks_url_combinations() {
        let mut def = parse(minimal_json());
        let jwt = |signing_method,
                   secret: Option<&str>,
                   public_key_pem: Option<&str>,
                   jwks_url: Option<&str>,
                   jwks_refresh_secs| AuthConfig::Jwt {
            signing_method,
            secret: secret.map(Into::into),
            public_key_pem: public_key_pem.map(Into::into),
            jwks_url: jwks_url.map(Into::into),
            jwks_refresh_secs,
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: "sub".into(),
        };

        // rs256 with only a jwks_url: valid, with or without a refresh interval.
        def.auth = jwt(
            JwtSigningMethod::Rs256,
            None,
            None,
            Some("https://idp.internal/jwks.json"),
            None,
        );
        def.validate().expect("rs256 with jwks_url is valid");
        def.auth = jwt(
            JwtSigningMethod::Rs256,
            None,
            None,
            Some("http://idp.internal/jwks.json"),
            Some(60),
        );
        def.validate()
            .expect("plain-http jwks_url with interval is valid");

        // rs256 with both key sources, or neither: invalid.
        def.auth = jwt(
            JwtSigningMethod::Rs256,
            None,
            Some("-----BEGIN PUBLIC KEY-----"),
            Some("https://idp.internal/jwks.json"),
            None,
        );
        assert!(def.validate().is_err());
        def.auth = jwt(JwtSigningMethod::Rs256, None, None, None, None);
        assert!(def.validate().is_err());

        // hs256 rejects jwks fields.
        def.auth = jwt(
            JwtSigningMethod::Hs256,
            Some("shhh"),
            None,
            Some("https://idp.internal/jwks.json"),
            None,
        );
        assert!(def.validate().is_err());

        // Malformed URL, refresh interval without a URL, zero interval.
        def.auth = jwt(JwtSigningMethod::Rs256, None, None, Some("not a url"), None);
        assert!(def.validate().is_err());
        def.auth = jwt(
            JwtSigningMethod::Rs256,
            None,
            Some("-----BEGIN PUBLIC KEY-----"),
            None,
            Some(60),
        );
        assert!(def.validate().is_err());
        def.auth = jwt(
            JwtSigningMethod::Rs256,
            None,
            None,
            Some("https://idp.internal/jwks.json"),
            Some(0),
        );
        assert!(def.validate().is_err());
    }

    #[test]
    fn jwt_jwks_config_round_trips_through_json() {
        let json = r#"{
            "api_id": "j",
            "name": "j",
            "listen_path": "/j/",
            "target_url": "http://j.internal",
            "auth": {
                "mode": "jwt",
                "signing_method": "rs256",
                "jwks_url": "https://idp.internal/jwks.json",
                "jwks_refresh_secs": 120
            }
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        let serialized = serde_json::to_string(&def).expect("serializes");
        let back: ApiDefinition = serde_json::from_str(&serialized).expect("parses back");
        assert_eq!(back.auth, def.auth);
        match def.auth {
            AuthConfig::Jwt {
                jwks_url,
                jwks_refresh_secs,
                ..
            } => {
                assert_eq!(jwks_url.as_deref(), Some("https://idp.internal/jwks.json"));
                assert_eq!(jwks_refresh_secs, Some(120));
            }
            other => panic!("expected jwt auth, got {other:?}"),
        }
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
    fn oidc_json_defaults_and_round_trips() {
        let json = r#"{
            "api_id": "o",
            "name": "o",
            "listen_path": "/o/",
            "target_url": "http://o.internal",
            "auth": {
                "mode": "oidc",
                "issuer_url": "https://idp.example.com/realm",
                "audiences": ["g2way-api"]
            }
        }"#;
        let def = parse(json);
        def.validate().expect("minimal oidc definition is valid");
        assert_eq!(def.auth.mode_name(), "oidc");
        match &def.auth {
            AuthConfig::Oidc {
                issuer_url,
                audiences,
                jwks_url,
                jwks_refresh_secs,
                header,
                identity_claim,
                policy_claim,
                policy_map,
            } => {
                assert_eq!(issuer_url, "https://idp.example.com/realm");
                assert_eq!(audiences, &["g2way-api"]);
                assert!(jwks_url.is_none() && jwks_refresh_secs.is_none());
                assert_eq!(header, DEFAULT_AUTH_HEADER);
                assert_eq!(identity_claim, DEFAULT_IDENTITY_CLAIM);
                assert_eq!(policy_claim, DEFAULT_OIDC_POLICY_CLAIM);
                assert!(policy_map.is_empty());
            }
            other => panic!("expected oidc auth, got {other:?}"),
        }
        let serialized = serde_json::to_string(&def).expect("serializes");
        let back: ApiDefinition = serde_json::from_str(&serialized).expect("parses back");
        assert_eq!(back.auth, def.auth);
    }

    #[test]
    fn oidc_requires_audiences_in_json() {
        // `audiences` has no serde default: omitting it is a parse error,
        // not a validation error — the config cannot even express an
        // audience-free OIDC API.
        let json = r#"{
            "api_id": "o",
            "name": "o",
            "listen_path": "/o/",
            "target_url": "http://o.internal",
            "auth": { "mode": "oidc", "issuer_url": "https://idp.example.com" }
        }"#;
        assert!(serde_json::from_str::<ApiDefinition>(json).is_err());
    }

    #[test]
    fn oidc_validation_rejects_bad_configs() {
        let mut def = parse(minimal_json());
        let oidc = |issuer_url: &str,
                    audiences: &[&str],
                    jwks_url: Option<&str>,
                    jwks_refresh_secs,
                    policy_map: &[(&str, &str)]| AuthConfig::Oidc {
            issuer_url: issuer_url.into(),
            audiences: audiences.iter().map(|a| (*a).into()).collect(),
            jwks_url: jwks_url.map(Into::into),
            jwks_refresh_secs,
            header: DEFAULT_AUTH_HEADER.into(),
            identity_claim: DEFAULT_IDENTITY_CLAIM.into(),
            policy_claim: DEFAULT_OIDC_POLICY_CLAIM.into(),
            policy_map: policy_map
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        };

        // Valid baselines: discovery-based and direct-jwks configurations.
        def.auth = oidc("https://idp.example.com", &["aud"], None, None, &[]);
        def.validate().expect("discovery config is valid");
        def.auth = oidc(
            "https://idp.example.com",
            &["aud"],
            Some("https://idp.example.com/jwks.json"),
            Some(60),
            &[("client-a", "gold")],
        );
        def.validate().expect("direct-jwks config is valid");

        let rejected = [
            // Empty or blank audiences.
            oidc("https://idp.example.com", &[], None, None, &[]),
            oidc("https://idp.example.com", &["ok", " "], None, None, &[]),
            // Issuer not a URL / wrong scheme / query / fragment.
            oidc("not a url", &["aud"], None, None, &[]),
            oidc("ftp://idp.example.com", &["aud"], None, None, &[]),
            oidc("https://idp.example.com/?x=1", &["aud"], None, None, &[]),
            oidc("https://idp.example.com/#frag", &["aud"], None, None, &[]),
            // Bad jwks_url, zero refresh interval.
            oidc("https://idp.example.com", &["aud"], Some("nope"), None, &[]),
            oidc("https://idp.example.com", &["aud"], None, Some(0), &[]),
            // Blank policy-map entries.
            oidc(
                "https://idp.example.com",
                &["aud"],
                None,
                None,
                &[(" ", "p")],
            ),
            oidc(
                "https://idp.example.com",
                &["aud"],
                None,
                None,
                &[("c", "")],
            ),
        ];
        for (i, auth) in rejected.into_iter().enumerate() {
            def.auth = auth;
            assert!(def.validate().is_err(), "case {i} must be rejected");
        }

        // Empty identity/policy claims and bad headers are rejected too.
        for patch in [
            |a: &mut AuthConfig| {
                if let AuthConfig::Oidc { identity_claim, .. } = a {
                    *identity_claim = " ".into();
                }
            },
            |a: &mut AuthConfig| {
                if let AuthConfig::Oidc { policy_claim, .. } = a {
                    *policy_claim = String::new();
                }
            },
            |a: &mut AuthConfig| {
                if let AuthConfig::Oidc { header, .. } = a {
                    *header = "bad header\n".into();
                }
            },
        ] {
            let mut auth = oidc("https://idp.example.com", &["aud"], None, None, &[]);
            patch(&mut auth);
            def.auth = auth;
            assert!(def.validate().is_err());
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
    fn hmac_json_defaults_and_round_trips() {
        let json = r#"{
            "api_id": "h",
            "name": "h",
            "listen_path": "/h/",
            "target_url": "http://h.internal",
            "auth": { "mode": "hmac" }
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        assert_eq!(
            def.auth,
            AuthConfig::Hmac {
                allowed_algorithms: vec![
                    HmacAlgorithm::HmacSha256,
                    HmacAlgorithm::HmacSha384,
                    HmacAlgorithm::HmacSha512,
                ],
                allowed_clock_skew_secs: Some(DEFAULT_HMAC_CLOCK_SKEW_SECS),
            }
        );
        assert_eq!(def.auth.mode_name(), "hmac");
        // The wire names are the draft-cavage algorithm names, and the skew
        // field is never skip-serialized (an explicit `null` — disabled —
        // must not round-trip back into the 300s default).
        let out = serde_json::to_string(&def.auth).expect("serialize");
        assert!(out.contains("hmac-sha256"), "got: {out}");
        assert!(
            out.contains("\"allowed_clock_skew_secs\":300"),
            "got: {out}"
        );
    }

    #[test]
    fn hmac_explicit_null_skew_disables_and_round_trips() {
        let auth: AuthConfig = serde_json::from_str(
            r#"{ "mode": "hmac", "allowed_clock_skew_secs": null,
                 "allowed_algorithms": ["hmac-sha256"] }"#,
        )
        .expect("parses");
        assert_eq!(
            auth,
            AuthConfig::Hmac {
                allowed_algorithms: vec![HmacAlgorithm::HmacSha256],
                allowed_clock_skew_secs: None,
            }
        );
        let out = serde_json::to_string(&auth).expect("serialize");
        let back: AuthConfig = serde_json::from_str(&out).expect("round-trips");
        assert_eq!(back, auth, "null skew must survive a round-trip");
    }

    #[test]
    fn hmac_invalid_settings_are_rejected() {
        let mut def = parse(minimal_json());
        def.auth = AuthConfig::Hmac {
            allowed_algorithms: vec![],
            allowed_clock_skew_secs: Some(300),
        };
        assert!(def.validate().is_err(), "empty algorithm list rejected");

        def.auth = AuthConfig::Hmac {
            allowed_algorithms: vec![HmacAlgorithm::HmacSha256, HmacAlgorithm::HmacSha256],
            allowed_clock_skew_secs: Some(300),
        };
        assert!(def.validate().is_err(), "duplicate algorithms rejected");

        def.auth = AuthConfig::Hmac {
            allowed_algorithms: vec![HmacAlgorithm::HmacSha256],
            allowed_clock_skew_secs: Some(0),
        };
        assert!(
            def.validate().is_err(),
            "zero skew rejected (null disables)"
        );

        assert!(
            serde_json::from_str::<AuthConfig>(
                r#"{ "mode": "hmac", "allowed_algorithms": ["hmac-sha1"] }"#
            )
            .is_err(),
            "hmac-sha1 is not a valid algorithm"
        );
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
    fn endpoint_rate_limits_parse_and_validate() {
        let json = r#"{
            "api_id": "e",
            "name": "e",
            "listen_path": "/e/",
            "target_url": "http://e.internal",
            "endpoint_rate_limits": [
                {"pattern": "^/e/search", "methods": ["POST"],
                 "rate": {"requests": 10, "per_seconds": 60}}
            ]
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        assert_eq!(def.endpoint_rate_limits[0].rate.requests, 10);

        // Stays off the wire when empty (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        assert!(!bare.contains("endpoint_rate_limits"));

        // A broken rule fails validation, naming the list.
        let mut def = parse(minimal_json());
        def.endpoint_rate_limits = vec![super::EndpointRateLimit {
            pattern: "^/x$".into(),
            methods: vec![],
            rate: crate::session::RateLimit {
                requests: 0,
                per_seconds: 60,
            },
        }];
        let err = def.validate().unwrap_err().to_string();
        assert!(err.contains("endpoint_rate_limits[0]"), "got: {err}");
    }

    #[test]
    fn cors_ip_lists_and_size_limit_parse_and_validate() {
        let json = r#"{
            "api_id": "s",
            "name": "s",
            "listen_path": "/s/",
            "target_url": "http://s.internal",
            "cors": {"allowed_origins": ["https://app.example.com"]},
            "allow_ips": ["10.0.0.0/8"],
            "block_ips": ["10.1.2.3"],
            "max_request_body_bytes": 1048576
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        assert!(def.cors.is_some());
        assert_eq!(def.max_request_body_bytes, Some(1_048_576));

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        for field in ["cors", "allow_ips", "block_ips", "max_request_body_bytes"] {
            assert!(!bare.contains(field), "`{field}` serialized when unset");
        }

        // Broken entries in each new field fail validation.
        let mut def = parse(minimal_json());
        def.cors = Some(serde_json::from_str(r#"{"allowed_origins": ["nope"]}"#).expect("parses"));
        assert!(def.validate().is_err(), "bad origin");

        let mut def = parse(minimal_json());
        def.allow_ips = vec!["not-an-ip".into()];
        assert!(def.validate().is_err(), "bad allow_ips entry");

        let mut def = parse(minimal_json());
        def.block_ips = vec!["10.0.0.0/99".into()];
        assert!(def.validate().is_err(), "bad block_ips prefix");

        let mut def = parse(minimal_json());
        def.max_request_body_bytes = Some(0);
        assert!(def.validate().is_err(), "zero size limit");
    }

    #[test]
    fn target_list_parses_and_validates() {
        let json = r#"{
            "api_id": "lb",
            "name": "lb",
            "listen_path": "/lb/",
            "target_url": "http://primary.internal",
            "target_list": ["http://a.internal", "https://b.internal:8443/base"]
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        assert_eq!(def.target_list.len(), 2);

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        assert!(!bare.contains("target_list"), "`target_list` serialized");

        // A broken entry fails validation, naming its index.
        let mut def = parse(minimal_json());
        def.target_list = vec!["http://ok.internal".into(), "not-a-url".into()];
        let err = def.validate().unwrap_err().to_string();
        assert!(err.contains("target_list[1]"), "got: {err}");

        let mut def = parse(minimal_json());
        def.target_list = vec!["ftp://x.example".into()];
        assert!(def.validate().is_err(), "non-http scheme accepted");
    }

    #[test]
    fn health_check_parses_defaults_and_validates() {
        let json = r#"{
            "api_id": "hc",
            "name": "hc",
            "listen_path": "/hc/",
            "target_url": "http://primary.internal",
            "target_list": ["http://a.internal", "http://b.internal"],
            "health_check": {}
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        let hc = def.health_check.as_ref().expect("set");
        assert_eq!(hc.path, DEFAULT_HEALTH_CHECK_PATH);
        assert_eq!(hc.interval_ms, 10_000);
        assert_eq!(hc.timeout_ms, 2_000);
        assert_eq!(hc.unhealthy_threshold, 3);
        assert_eq!(hc.healthy_threshold, 2);

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        assert!(!bare.contains("health_check"), "`health_check` serialized");

        // Each invalid setting is rejected.
        let mut def = parse(json);
        let base = def.health_check.clone().expect("set");
        for (label, broken) in [
            (
                "relative path",
                HealthCheckConfig {
                    path: "health".into(),
                    ..base.clone()
                },
            ),
            (
                "non-URL path",
                HealthCheckConfig {
                    path: "/with space".into(),
                    ..base.clone()
                },
            ),
            (
                "zero interval",
                HealthCheckConfig {
                    interval_ms: 0,
                    ..base.clone()
                },
            ),
            (
                "zero timeout",
                HealthCheckConfig {
                    timeout_ms: 0,
                    ..base.clone()
                },
            ),
            (
                "zero unhealthy",
                HealthCheckConfig {
                    unhealthy_threshold: 0,
                    ..base.clone()
                },
            ),
            (
                "zero healthy",
                HealthCheckConfig {
                    healthy_threshold: 0,
                    ..base.clone()
                },
            ),
        ] {
            def.health_check = Some(broken);
            assert!(def.validate().is_err(), "`{label}` accepted");
        }
    }

    #[test]
    fn service_discovery_parses_defaults_and_validates() {
        let json = r#"{
            "api_id": "sd",
            "name": "sd",
            "listen_path": "/sd/",
            "target_url": "http://seed.internal",
            "service_discovery": {"endpoint": "http://consul.internal:8500/v1/catalog/service/users"}
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        let sd = def.service_discovery.as_ref().expect("set");
        assert_eq!(sd.data_path, "");
        assert_eq!(sd.port_data_path, None);
        assert_eq!(sd.parent_data_path, None);
        assert_eq!(sd.scheme, DEFAULT_DISCOVERY_SCHEME);
        assert_eq!(sd.interval_ms, 10_000);
        assert_eq!(sd.timeout_ms, 5_000);

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        assert!(
            !bare.contains("service_discovery"),
            "`service_discovery` serialized"
        );
        let set = serde_json::to_string(&def).expect("serializes");
        assert!(
            !set.contains("port_data_path"),
            "unset sub-field serialized"
        );
    }

    #[test]
    fn service_discovery_rejects_invalid_settings() {
        let base = ServiceDiscoveryConfig {
            endpoint: "http://catalog.internal/services".into(),
            data_path: String::new(),
            port_data_path: None,
            parent_data_path: None,
            scheme: "http".into(),
            interval_ms: 10_000,
            timeout_ms: 5_000,
        };
        let mut def = parse(minimal_json());
        for (label, broken) in [
            (
                "non-http endpoint",
                ServiceDiscoveryConfig {
                    endpoint: "ftp://catalog.internal".into(),
                    ..base.clone()
                },
            ),
            (
                "relative endpoint",
                ServiceDiscoveryConfig {
                    endpoint: "/services".into(),
                    ..base.clone()
                },
            ),
            (
                "bad scheme",
                ServiceDiscoveryConfig {
                    scheme: "grpc".into(),
                    ..base.clone()
                },
            ),
            (
                "zero interval",
                ServiceDiscoveryConfig {
                    interval_ms: 0,
                    ..base.clone()
                },
            ),
            (
                "zero timeout",
                ServiceDiscoveryConfig {
                    timeout_ms: 0,
                    ..base.clone()
                },
            ),
            (
                "empty path segment",
                ServiceDiscoveryConfig {
                    data_path: "a..b".into(),
                    ..base.clone()
                },
            ),
            (
                "leading dot",
                ServiceDiscoveryConfig {
                    parent_data_path: Some(".data".into()),
                    ..base.clone()
                },
            ),
        ] {
            def.service_discovery = Some(broken);
            assert!(def.validate().is_err(), "`{label}` accepted");
        }
    }

    #[test]
    fn service_discovery_extracts_entries() {
        let sd = |json: &str| -> ServiceDiscoveryConfig {
            serde_json::from_str(json).expect("valid discovery JSON")
        };
        let entry = |host: &str, port: Option<u16>| DiscoveredEntry {
            host: host.to_owned(),
            port,
        };

        for (label, config, doc, expected) in [
            (
                "bare array of strings, empty data_path",
                sd(r#"{"endpoint": "http://c.internal"}"#),
                serde_json::json!(["a.internal", "b.internal:9000"]),
                vec![entry("a.internal", None), entry("b.internal:9000", None)],
            ),
            (
                "single string under a dotted path",
                sd(r#"{"endpoint": "http://c.internal", "data_path": "node.ip"}"#),
                serde_json::json!({"node": {"ip": "10.0.0.7"}}),
                vec![entry("10.0.0.7", None)],
            ),
            (
                "consul-style root array via empty parent_data_path",
                sd(r#"{"endpoint": "http://c.internal", "parent_data_path": "",
                        "data_path": "Address", "port_data_path": "ServicePort"}"#),
                serde_json::json!([
                    {"Address": "10.0.0.1", "ServicePort": 8300},
                    {"Address": "10.0.0.2", "ServicePort": 8301}
                ]),
                vec![entry("10.0.0.1", Some(8300)), entry("10.0.0.2", Some(8301))],
            ),
            (
                "nested parent path with numeric array index and string port",
                sd(
                    r#"{"endpoint": "http://c.internal", "parent_data_path": "data.nodes",
                        "data_path": "addrs.0", "port_data_path": "port"}"#,
                ),
                serde_json::json!({"data": {"nodes": [
                    {"addrs": ["x.internal", "ignored"], "port": "7000"}
                ]}}),
                vec![entry("x.internal", Some(7000))],
            ),
            (
                "root-level port applied to every entry",
                sd(r#"{"endpoint": "http://c.internal", "data_path": "hosts",
                        "port_data_path": "port"}"#),
                serde_json::json!({"hosts": ["a.internal", "b.internal"], "port": 8080}),
                vec![
                    entry("a.internal", Some(8080)),
                    entry("b.internal", Some(8080)),
                ],
            ),
            (
                "full URLs pass through untouched",
                sd(r#"{"endpoint": "http://c.internal"}"#),
                serde_json::json!(["https://a.internal:8443/base"]),
                vec![entry("https://a.internal:8443/base", None)],
            ),
        ] {
            let entries = config
                .extract_entries(&doc)
                .unwrap_or_else(|e| panic!("`{label}` failed: {e}"));
            assert_eq!(entries, expected, "`{label}`");
        }
    }

    #[test]
    fn service_discovery_extraction_errors() {
        let sd = |json: &str| -> ServiceDiscoveryConfig {
            serde_json::from_str(json).expect("valid discovery JSON")
        };
        for (label, config, doc, needle) in [
            (
                "parent path not an array",
                sd(r#"{"endpoint": "http://c.internal", "parent_data_path": "svc"}"#),
                serde_json::json!({"svc": {"a": 1}}),
                "is not an array",
            ),
            (
                "missing parent path",
                sd(r#"{"endpoint": "http://c.internal", "parent_data_path": "svc"}"#),
                serde_json::json!({"other": []}),
                "not found",
            ),
            (
                "missing data path",
                sd(r#"{"endpoint": "http://c.internal", "data_path": "hosts"}"#),
                serde_json::json!({"other": []}),
                "not found",
            ),
            (
                "non-string host element",
                sd(r#"{"endpoint": "http://c.internal", "data_path": "hosts"}"#),
                serde_json::json!({"hosts": ["ok.internal", 42]}),
                "not a non-empty string",
            ),
            (
                "empty host string",
                sd(r#"{"endpoint": "http://c.internal"}"#),
                serde_json::json!("  "),
                "not a non-empty string",
            ),
            (
                "non-string host in parent element",
                sd(r#"{"endpoint": "http://c.internal", "parent_data_path": "",
                        "data_path": "ip"}"#),
                serde_json::json!([{"ip": 42}]),
                "not a non-empty string",
            ),
            (
                "port zero",
                sd(r#"{"endpoint": "http://c.internal", "data_path": "hosts",
                        "port_data_path": "port"}"#),
                serde_json::json!({"hosts": ["a"], "port": 0}),
                "between 1 and 65535",
            ),
            (
                "port too large",
                sd(r#"{"endpoint": "http://c.internal", "data_path": "hosts",
                        "port_data_path": "port"}"#),
                serde_json::json!({"hosts": ["a"], "port": 70000}),
                "between 1 and 65535",
            ),
            (
                "non-numeric port string",
                sd(r#"{"endpoint": "http://c.internal", "data_path": "hosts",
                        "port_data_path": "port"}"#),
                serde_json::json!({"hosts": ["a"], "port": "eighty"}),
                "between 1 and 65535",
            ),
        ] {
            let err = config
                .extract_entries(&doc)
                .expect_err(&format!("`{label}` accepted"));
            assert!(err.contains(needle), "`{label}`: got `{err}`");
        }
    }

    #[test]
    fn circuit_breaker_and_retries_parse_defaults_and_validate() {
        let json = r#"{
            "api_id": "cb",
            "name": "cb",
            "listen_path": "/cb/",
            "target_url": "http://primary.internal",
            "circuit_breaker": {},
            "upstream_retries": 2
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        let cb = def.circuit_breaker.as_ref().expect("set");
        assert_eq!(cb.failure_threshold, 5);
        assert_eq!(cb.cooldown_ms, 30_000);
        assert_eq!(def.upstream_retries, 2);

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        for field in ["circuit_breaker", "upstream_retries"] {
            assert!(!bare.contains(field), "`{field}` serialized when unset");
        }

        let mut def = parse(json);
        def.circuit_breaker = Some(CircuitBreakerConfig {
            failure_threshold: 0,
            cooldown_ms: 1000,
        });
        assert!(def.validate().is_err(), "zero threshold accepted");

        let mut def = parse(json);
        def.circuit_breaker = Some(CircuitBreakerConfig {
            failure_threshold: 5,
            cooldown_ms: 0,
        });
        assert!(def.validate().is_err(), "zero cooldown accepted");

        let mut def = parse(minimal_json());
        def.upstream_retries = 11;
        let err = def.validate().unwrap_err().to_string();
        assert!(err.contains("upstream_retries"), "got: {err}");
    }

    #[test]
    fn enable_upgrades_defaults_off_and_round_trips() {
        let def = parse(minimal_json());
        assert!(!def.enable_upgrades, "upgrades must be an explicit opt-in");
        // The default-off flag stays off the wire (old records unaffected).
        let bare = serde_json::to_string(&def).expect("serializes");
        assert!(!bare.contains("enable_upgrades"), "serialized when unset");

        let mut def = parse(minimal_json());
        def.enable_upgrades = true;
        def.validate().expect("valid");
        let json = serde_json::to_string(&def).expect("serializes");
        let back: ApiDefinition = serde_json::from_str(&json).expect("parses");
        assert!(back.enable_upgrades);
    }

    #[test]
    fn upstream_http2_defaults_off_and_round_trips() {
        let def = parse(minimal_json());
        assert!(
            !def.upstream_http2,
            "HTTP/2 upstreams must be an explicit opt-in"
        );
        // The default-off flag stays off the wire (old records unaffected).
        let bare = serde_json::to_string(&def).expect("serializes");
        assert!(!bare.contains("upstream_http2"), "serialized when unset");

        let mut def = parse(minimal_json());
        def.upstream_http2 = true;
        def.validate().expect("valid");
        let json = serde_json::to_string(&def).expect("serializes");
        let back: ApiDefinition = serde_json::from_str(&json).expect("parses");
        assert!(back.upstream_http2);
    }

    #[test]
    fn upstream_http2_rejects_enable_upgrades() {
        let mut def = parse(minimal_json());
        def.upstream_http2 = true;
        def.enable_upgrades = true;
        let err = def.validate().unwrap_err().to_string();
        assert!(err.contains("upstream_http2"), "got: {err}");
        assert!(err.contains("enable_upgrades"), "got: {err}");
    }

    /// A definition with a subscriptions-enabled GraphQL block.
    fn subscriptions_def() -> ApiDefinition {
        let mut def = parse(minimal_json());
        def.graphql = Some(
            serde_json::from_value(serde_json::json!({
                "schema": "type Query { hello: String } type Subscription { ticks: Int }",
                "subscriptions": {}
            }))
            .expect("parses"),
        );
        def
    }

    #[test]
    fn graphql_subscriptions_enabled_truth_table() {
        assert!(!parse(minimal_json()).graphql_subscriptions_enabled());

        let def = subscriptions_def();
        def.validate().expect("valid");
        assert!(def.graphql_subscriptions_enabled());

        // The graphql-level kill switch turns subscriptions off with it.
        let mut def = subscriptions_def();
        def.graphql.as_mut().expect("set").enabled = false;
        assert!(!def.graphql_subscriptions_enabled());

        // So does the subscriptions-level one.
        let mut def = subscriptions_def();
        def.graphql
            .as_mut()
            .expect("set")
            .subscriptions
            .as_mut()
            .expect("set")
            .enabled = false;
        assert!(!def.graphql_subscriptions_enabled());

        // A graphql block without a subscriptions block: off.
        let mut def = subscriptions_def();
        def.graphql.as_mut().expect("set").subscriptions = None;
        assert!(!def.graphql_subscriptions_enabled());
    }

    #[test]
    fn upstream_http2_rejects_graphql_subscriptions() {
        let mut def = subscriptions_def();
        def.upstream_http2 = true;
        let err = def.validate().unwrap_err().to_string();
        assert!(err.contains("upstream_http2"), "got: {err}");
        assert!(err.contains("graphql.subscriptions"), "got: {err}");
    }

    #[test]
    fn cache_parses_defaults_and_validates() {
        let json = r#"{
            "api_id": "c",
            "name": "c",
            "listen_path": "/c/",
            "target_url": "http://c.internal",
            "cache": {}
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        let cache = def.cache.as_ref().expect("set");
        assert_eq!(cache.ttl_secs, 60);
        assert_eq!(cache.max_body_bytes, 1_048_576);

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        assert!(!bare.contains("cache"), "`cache` serialized when unset");

        let mut def = parse(json);
        def.cache = Some(CacheConfig {
            ttl_secs: 0,
            max_body_bytes: 1024,
        });
        assert!(def.validate().is_err(), "zero ttl accepted");

        let mut def = parse(json);
        def.cache = Some(CacheConfig {
            ttl_secs: 60,
            max_body_bytes: 0,
        });
        assert!(def.validate().is_err(), "zero body cap accepted");
    }

    #[test]
    fn versioning_parses_and_validates() {
        let json = r#"{
            "api_id": "v",
            "name": "v",
            "listen_path": "/v/",
            "target_url": "http://v.internal",
            "versioning": {
                "default_version": "v1",
                "versions": {
                    "v1": {},
                    "v2": {"target_url": "http://v2.internal"}
                }
            }
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        assert_eq!(def.versioning.as_ref().expect("set").versions.len(), 2);

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        assert!(!bare.contains("versioning"), "`versioning` serialized");

        // A broken version override fails the definition's own validation.
        let mut def = parse(json);
        if let Some(v) = &mut def.versioning {
            v.versions.get_mut("v2").expect("v2").target_url = Some("not-a-url".into());
        }
        let err = def.validate().unwrap_err().to_string();
        assert!(err.contains("version `v2`"), "got: {err}");
    }

    #[test]
    fn graphql_config_parses_and_validates() {
        let json = r#"{
            "api_id": "gql",
            "name": "gql",
            "listen_path": "/gql/",
            "target_url": "http://gql.internal/graphql",
            "graphql": {
                "schema": "type Query { hello: String }",
                "max_query_depth": 4
            }
        }"#;
        let def = parse(json);
        def.validate().expect("valid");
        let gql = def.graphql.as_ref().expect("set");
        assert!(gql.enabled && gql.introspection_enabled);
        assert_eq!(gql.max_query_depth, Some(4));

        // Optionals stay off the wire when unset (old records unaffected).
        let bare = serde_json::to_string(&parse(minimal_json())).expect("serializes");
        assert!(!bare.contains("graphql"), "`graphql` serialized when unset");

        // A broken schema fails validation, naming the API.
        let mut def = parse(json);
        def.graphql.as_mut().expect("set").schema = "type Query {".into();
        let err = def.validate().unwrap_err().to_string();
        assert!(
            err.contains("gql") && err.contains("graphql.schema"),
            "got: {err}"
        );
    }

    #[test]
    fn storage_key_follows_schema() {
        assert_eq!(
            api_definition_storage_key("default", "httpbin"),
            "g2:default:apidef:httpbin"
        );
        assert_eq!(api_definition_key_prefix("default"), "g2:default:apidef:");
        assert_eq!(
            response_cache_key_prefix("default", "httpbin:v2"),
            "g2:default:cache:httpbin:v2:"
        );
    }

    #[test]
    fn target_uri_round_trips() {
        let def = parse(minimal_json());
        let uri = def.target_uri();
        assert_eq!(uri.host(), Some("users.internal"));
        assert_eq!(uri.port_u16(), Some(8000));
    }
}
