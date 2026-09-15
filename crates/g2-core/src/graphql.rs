//! GraphQL configuration for one API (milestone M9): proxy-mode settings,
//! protection limits, the gateway-served playground, and persisted
//! GraphQL-as-REST queries.
//!
//! The model here is pure configuration — parsing and validation. The
//! runtime enforcement lives in `g2-middleware` (`GraphQlLayer`),
//! precompiled at route-build time so the hot path parses only the request
//! payload, never configuration (ADR-0001, ADR-0004).
//!
//! The GraphQL schema (SDL) lives **in the API definition** and is
//! validated with apollo-compiler when the definition is written or loaded:
//! a broken schema fails loudly at `POST /g2/apis` (or file load), never at
//! request time.

use std::collections::BTreeMap;

use http::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::transform::{HOP_BY_HOP, TRANSFORM_METHODS};
use crate::Error;

/// Playground path used when a [`PlaygroundConfig`] does not name one,
/// relative to the API's listen path.
pub const DEFAULT_PLAYGROUND_PATH: &str = "/playground";

/// Default [`SchemaSyncConfig::interval_ms`]: ten minutes.
pub const DEFAULT_SCHEMA_SYNC_INTERVAL_MS: u64 = 600_000;

/// Default [`SchemaSyncConfig::timeout_ms`]: ten seconds.
pub const DEFAULT_SCHEMA_SYNC_TIMEOUT_MS: u64 = 10_000;

/// Default cap on a UDG data-source response body: 4 MiB (the schema-sync
/// introspection cap).
pub const DEFAULT_UDG_MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

fn default_playground_path() -> String {
    DEFAULT_PLAYGROUND_PATH.to_owned()
}

fn default_sync_interval_ms() -> u64 {
    DEFAULT_SCHEMA_SYNC_INTERVAL_MS
}

fn default_sync_timeout_ms() -> u64 {
    DEFAULT_SCHEMA_SYNC_TIMEOUT_MS
}

fn default_true() -> bool {
    true
}

/// How the gateway executes GraphQL for an API.
///
/// The enum is the extension point for later M9 modes (federation
/// supergraph and subgraph).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphQlExecutionMode {
    /// Pass-through proxy to a single upstream GraphQL server: the
    /// gateway validates and polices the query, then
    /// forwards it unchanged — it never executes GraphQL itself.
    #[default]
    Proxy,

    /// Universal Data Graph: the gateway executes
    /// queries itself, resolving each root field through the data source
    /// mapped in [`GraphQlConfig::data_sources`] and stitching the results
    /// into one GraphQL response. Nothing is forwarded to
    /// [`target_url`](crate::ApiDefinition::target_url) (ADR-0010).
    Udg,
}

/// GraphQL settings for one API (see [`ApiDefinition::graphql`]).
///
/// Present on a definition, the API is treated as a GraphQL API: requests
/// are parsed as GraphQL, validated against [`schema`](Self::schema), and
/// policed (depth limits, introspection control, per-key field permissions
/// from [`ApiAccess`](crate::session::ApiAccess)) before being forwarded.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "schema": "type Query { hello: String }",
///   "max_query_depth": 8,
///   "introspection_enabled": false,
///   "playground": { "path": "/playground" }
/// }
/// ```
///
/// [`ApiDefinition::graphql`]: crate::ApiDefinition::graphql
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphQlConfig {
    /// Kill switch: `false` disables all GraphQL handling for the API while
    /// keeping the configuration in place (the config is still validated).
    /// Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// How the gateway executes GraphQL. Defaults to (and currently only
    /// supports) [`GraphQlExecutionMode::Proxy`].
    #[serde(default)]
    pub execution_mode: GraphQlExecutionMode,

    /// The API's GraphQL schema in SDL form. Required; validated with
    /// apollo-compiler at write/load time. Incoming queries are validated
    /// against it — an unknown field or type never reaches the upstream.
    pub schema: String,

    /// Whether introspection queries (`__schema` / `__type`) are allowed.
    /// Defaults to `true`; keys can additionally disable introspection for
    /// themselves via
    /// [`ApiAccess::disable_introspection`](crate::session::ApiAccess::disable_introspection).
    #[serde(default = "default_true")]
    pub introspection_enabled: bool,

    /// Maximum query depth (nested selection-set levels; `{ a { b } }` is
    /// depth 2). Deeper queries are rejected with `403`.
    /// Unset = unlimited; keys can override via
    /// [`ApiAccess::max_query_depth`](crate::session::ApiAccess::max_query_depth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_query_depth: Option<u32>,

    /// Optional gateway-served GraphiQL playground for this API. The page
    /// sits behind the API's full middleware chain, so a protected API's
    /// playground requires credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub playground: Option<PlaygroundConfig>,

    /// Persisted GraphQL-as-REST endpoints: REST-shaped routes the gateway
    /// answers by building a GraphQL request server-side. Matched in
    /// order; the first match wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persisted_queries: Vec<PersistedQuery>,

    /// Periodic schema sync from upstream introspection. When set, each
    /// gateway pod polls the upstream's introspection endpoint and swaps
    /// the schema it validates against in memory (stale-on-error;
    /// [`schema`](Self::schema) stays required as the seed). Unset = the
    /// schema is static (ADR-0008).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_sync: Option<SchemaSyncConfig>,

    /// GraphQL subscriptions over WebSocket. When set (and enabled), the
    /// gateway accepts `graphql-transport-ws` / `graphql-ws` WebSocket
    /// handshakes on the listen path and polices every subscribe operation
    /// like an HTTP query (ADR-0009). Unset = WebSocket handshakes on the
    /// GraphQL endpoint are rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscriptions: Option<SubscriptionsConfig>,

    /// Universal Data Graph data sources, keyed `"<RootType>.<field>"`
    /// (e.g. `"Query.user"` — the schema's actual root operation type
    /// names). Required (and only allowed) when
    /// [`execution_mode`](Self::execution_mode) is
    /// [`Udg`](GraphQlExecutionMode::Udg); every field of the query and
    /// mutation root types must be mapped (ADR-0010).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data_sources: BTreeMap<String, UdgDataSource>,
}

/// GraphQL-subscriptions-over-WebSocket settings (see
/// [`GraphQlConfig::subscriptions`]).
///
/// The gateway terminates the WebSocket subprotocol on both legs: client
/// `subscribe`/`start` payloads are validated against the schema and the
/// per-key grants before being forwarded; violations are answered with
/// protocol-level `error` messages and never reach the upstream. Upstream
/// frames are relayed verbatim. Requires the schema to define a
/// `Subscription` root type.
///
/// # Example (JSON)
///
/// ```json
/// { "max_message_bytes": 262144 }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionsConfig {
    /// Kill switch inside the block; defaults to `true` (presence of the
    /// block enables subscriptions, like [`GraphQlConfig::playground`]).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Cap on a single client→gateway WebSocket message (must be > 0).
    /// Unset = the API's `max_request_body_bytes`, else 1 MiB — the same
    /// bound the HTTP-side body buffering uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_message_bytes: Option<u64>,
}

impl Default for SubscriptionsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_message_bytes: None,
        }
    }
}

fn default_rest_method() -> String {
    "GET".to_owned()
}

/// One Universal Data Graph data source (see
/// [`GraphQlConfig::data_sources`]): where the gateway fetches the value of
/// one root field in UDG mode.
///
/// # Example (JSON)
///
/// ```json
/// { "kind": "rest", "url": "http://users.internal/users/{{ args.id }}" }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UdgDataSource {
    /// A REST/JSON endpoint: the response body is the field's JSON value.
    Rest(UdgRestSource),

    /// An upstream GraphQL service: the gateway sends the root field's
    /// sub-selection as a standalone query and merges the response.
    Graphql(UdgGraphQlSource),
}

/// A REST data source for one UDG root field.
///
/// `url`, header values, and `body` are minijinja templates (ADR-0007's
/// engine), rendered per request against
/// `{ args, _g2: { method, path, headers, session: { alias } } }` where
/// `args` are the coerced GraphQL field arguments. The rendered URL must be
/// absolute `http(s)`. The response body is parsed as JSON and becomes the
/// field's value; nested selections are projected from it.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdgRestSource {
    /// HTTP method of the fetch (case-insensitive; `CONNECT` is not
    /// allowed). Defaults to `GET`.
    #[serde(default = "default_rest_method")]
    pub method: String,

    /// URL template. Rendered per request; the result must be an absolute
    /// `http(s)` URL.
    pub url: String,

    /// Extra headers on the fetch: name → value template. Hop-by-hop
    /// headers are rejected.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,

    /// Optional request-body template. Sent with
    /// `content-type: application/json` unless [`headers`](Self::headers)
    /// overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,

    /// Per-fetch timeout in milliseconds (must be > 0). Unset = the API's
    /// `upstream_timeout_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    /// Cap on the response body in bytes (must be > 0). Unset =
    /// [`DEFAULT_UDG_MAX_RESPONSE_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
}

/// A GraphQL data source for one UDG root field.
///
/// The gateway prints the requested field (selection set, aliases, and
/// arguments verbatim) together with the fragment definitions and variable
/// definitions its subtree uses, and `POST`s
/// `{"query": …, "variables": …}` to [`url`](Self::url). The response's
/// `data.<field>` becomes the field's value; its `errors` are appended to
/// the stitched response (message-only).
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdgGraphQlSource {
    /// Absolute `http(s)` URL of the upstream GraphQL endpoint (not
    /// templated).
    pub url: String,

    /// Extra headers on the fetch: name → value template (upstream auth).
    /// Hop-by-hop headers are rejected.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,

    /// Per-fetch timeout in milliseconds (must be > 0). Unset = the API's
    /// `upstream_timeout_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    /// Cap on the response body in bytes (must be > 0). Unset =
    /// [`DEFAULT_UDG_MAX_RESPONSE_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
}

impl UdgDataSource {
    /// Validates one data source; `key` names it in errors.
    fn validate(&self, key: &str, fail: &impl Fn(String) -> Error) -> Result<(), Error> {
        let field = |name: &str| format!("graphql.data_sources[\"{key}\"].{name}");
        let (headers, timeout_ms, max_response_bytes) = match self {
            Self::Rest(rest) => {
                if !TRANSFORM_METHODS
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(&rest.method))
                {
                    return Err(fail(format!(
                        "`{}` must be one of {} (got `{}`)",
                        field("method"),
                        TRANSFORM_METHODS.join(", "),
                        rest.method
                    )));
                }
                if rest.url.trim().is_empty() {
                    return Err(fail(format!("`{}` must not be empty", field("url"))));
                }
                validate_template(&rest.url, &field("url"), fail)?;
                if let Some(body) = &rest.body {
                    validate_template(body, &field("body"), fail)?;
                }
                (&rest.headers, rest.timeout_ms, rest.max_response_bytes)
            }
            Self::Graphql(gql) => {
                let valid = (gql.url.starts_with("http://") || gql.url.starts_with("https://"))
                    && gql.url.parse::<http::Uri>().is_ok();
                if !valid {
                    return Err(fail(format!(
                        "`{}` must be an absolute http(s) URL, got `{}`",
                        field("url"),
                        gql.url
                    )));
                }
                (&gql.headers, gql.timeout_ms, gql.max_response_bytes)
            }
        };
        for (name, value) in headers {
            if HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(fail(format!(
                    "`{}` name is not a valid header name: `{name}`",
                    field("headers")
                )));
            }
            if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                return Err(fail(format!(
                    "`{}` must not set hop-by-hop header `{name}`",
                    field("headers")
                )));
            }
            validate_template(value, &format!("{}.{name}", field("headers")), fail)?;
        }
        if timeout_ms == Some(0) {
            return Err(fail(format!(
                "`{}` must be greater than zero (omit it to inherit the API's \
                 `upstream_timeout_ms`)",
                field("timeout_ms")
            )));
        }
        if max_response_bytes == Some(0) {
            return Err(fail(format!(
                "`{}` must be greater than zero",
                field("max_response_bytes")
            )));
        }
        Ok(())
    }
}

/// Checks that a data-source template parses as minijinja (the
/// body-transform precedent: syntax errors are config-time errors).
fn validate_template(
    template: &str,
    field: &str,
    fail: &impl Fn(String) -> Error,
) -> Result<(), Error> {
    if let Err(err) = minijinja::Environment::new().template_from_str(template) {
        return Err(fail(format!(
            "`{field}` is not a valid minijinja template: {err}"
        )));
    }
    Ok(())
}

/// Schema-sync settings: how a pod fetches the upstream's schema via
/// GraphQL introspection (see [`GraphQlConfig::schema_sync`]).
///
/// The introspection `POST` goes to the API's own upstream (respecting
/// load balancing, service discovery, and health eviction) unless
/// [`url`](Self::url) points elsewhere. Every failure — transport, non-2xx,
/// invalid introspection JSON, a converted schema that does not compile, or
/// a persisted query invalid against the new schema — keeps the previous
/// schema serving and is surfaced on `GET /g2/node`.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "interval_ms": 300000,
///   "headers": { "authorization": "Bearer token" }
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaSyncConfig {
    /// Milliseconds between introspection fetches (must be > 0). Defaults
    /// to [`DEFAULT_SCHEMA_SYNC_INTERVAL_MS`]. An admin-triggered sync
    /// (`POST /g2/graphql/sync`) fetches immediately regardless.
    #[serde(default = "default_sync_interval_ms")]
    pub interval_ms: u64,

    /// Per-fetch timeout in milliseconds (must be > 0). Defaults to
    /// [`DEFAULT_SCHEMA_SYNC_TIMEOUT_MS`].
    #[serde(default = "default_sync_timeout_ms")]
    pub timeout_ms: u64,

    /// Absolute `http(s)` URL to introspect instead of the API's upstream —
    /// for when introspection is served elsewhere (e.g. an internal
    /// endpoint while the public one has introspection disabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Extra headers on the introspection request (upstream auth): name →
    /// literal value. Hop-by-hop headers are rejected.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

impl SchemaSyncConfig {
    fn validate(&self, fail: &impl Fn(String) -> Error) -> Result<(), Error> {
        if self.interval_ms == 0 {
            return Err(fail(
                "`graphql.schema_sync.interval_ms` must be greater than zero".into(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(fail(
                "`graphql.schema_sync.timeout_ms` must be greater than zero".into(),
            ));
        }
        if let Some(url) = &self.url {
            let valid = (url.starts_with("http://") || url.starts_with("https://"))
                && url.parse::<http::Uri>().is_ok();
            if !valid {
                return Err(fail(format!(
                    "`graphql.schema_sync.url` must be an absolute http(s) URL, got `{url}`"
                )));
            }
        }
        for (name, value) in &self.headers {
            if HeaderName::from_bytes(name.as_bytes()).is_err() {
                return Err(fail(format!(
                    "`graphql.schema_sync.headers` name is not a valid header name: `{name}`"
                )));
            }
            if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                return Err(fail(format!(
                    "`graphql.schema_sync.headers` must not set hop-by-hop header `{name}`"
                )));
            }
            if HeaderValue::from_str(value).is_err() {
                return Err(fail(format!(
                    "`graphql.schema_sync.headers` value for `{name}` is not a valid header value"
                )));
            }
        }
        Ok(())
    }
}

/// Settings for the gateway-served GraphQL playground.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaygroundConfig {
    /// Path the playground page is served on, relative to the API's listen
    /// path. Must start with `/`; defaults to [`DEFAULT_PLAYGROUND_PATH`].
    #[serde(default = "default_playground_path")]
    pub path: String,
}

impl Default for PlaygroundConfig {
    fn default() -> Self {
        Self {
            path: default_playground_path(),
        }
    }
}

/// One persisted GraphQL-as-REST endpoint.
///
/// A request matching `method` + `path` (relative to the listen path) is
/// rewritten by the gateway into a `POST` of `operation` to the upstream
/// GraphQL endpoint, with `variables` filled from the template below. The
/// persisted operation is subject to the same protections (depth,
/// introspection, field permissions) as a client-written query.
///
/// # Variable templating
///
/// `variables` must be a JSON object. String values are substituted:
///
/// - `"$path.<name>"` — the value of the `{<name>}` segment of `path`.
/// - `"$header.<name>"` — the value of request header `<name>` (JSON
///   `null` when the header is absent).
///
/// Substitution recurses into nested objects and arrays; all other values
/// are passed through verbatim.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "method": "GET",
///   "path": "/users/{id}",
///   "operation": "query User($id: ID!) { user(id: $id) { name } }",
///   "variables": { "id": "$path.id" }
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedQuery {
    /// HTTP method the endpoint answers (case-insensitive; `CONNECT` is not
    /// allowed).
    pub method: String,

    /// Path relative to the API's listen path. Must start with `/`. A
    /// segment of the form `{name}` matches any single segment and binds it
    /// for `$path.<name>` substitution; names must be unique.
    pub path: String,

    /// The GraphQL executable document sent upstream. Validated against the
    /// API's schema at write/load time.
    pub operation: String,

    /// Operation to execute when `operation` defines several. Must name an
    /// operation in the document; required in that case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,

    /// Variables template (a JSON object; see the type-level docs for the
    /// `$path.` / `$header.` substitution rules). Unset = no variables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub variables: Option<serde_json::Value>,
}

/// The `{name}` path parameters of a persisted-query path template, in
/// order of appearance.
///
/// Assumes the template has passed [`PersistedQuery`] validation; used by
/// the middleware to compile the matching regex with the same rules.
#[must_use]
pub fn path_template_params(path: &str) -> Vec<&str> {
    path.split('/')
        .filter_map(|seg| seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .collect()
}

/// Folds an apollo-compiler diagnostic list into one `;`-joined line of
/// messages (the CLI-report form spans many lines with source snippets —
/// too noisy for an error reason).
fn diagnostic_reasons(errors: &apollo_compiler::validation::DiagnosticList) -> String {
    errors
        .iter()
        .map(|d| d.error.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

impl GraphQlConfig {
    /// Validates the GraphQL settings; `api` names the owning definition in
    /// errors. Runs even when [`enabled`](Self::enabled) is `false` — a
    /// broken config should fail loudly, not lie dormant.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the schema is empty or
    /// not a valid GraphQL schema, `max_query_depth` is zero, a playground
    /// or persisted path breaks the path rules, a persisted query has an
    /// invalid method, path template, operation, operation name, or
    /// variables template, a schema-sync setting is invalid (zero
    /// interval/timeout, non-http(s) URL, bad or hop-by-hop header), a
    /// subscriptions message cap is zero, subscriptions are enabled on a
    /// schema without a `Subscription` root type, `data_sources` is set in
    /// proxy mode, or a `udg`-mode rule fails (schema sync or enabled
    /// subscriptions present, a data source missing, unknown, or invalid,
    /// or a persisted query selecting a subscription).
    pub fn validate(&self, api: &str) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason,
        };

        if self.schema.trim().is_empty() {
            return Err(fail("`graphql.schema` must not be empty".into()));
        }
        let schema = apollo_compiler::Schema::parse_and_validate(&self.schema, "schema.graphql")
            .map_err(|e| {
                fail(format!(
                    "`graphql.schema` is not a valid GraphQL schema: {}",
                    diagnostic_reasons(&e.errors)
                ))
            })?;

        if self.max_query_depth == Some(0) {
            return Err(fail(
                "`graphql.max_query_depth` must be greater than zero (omit it for unlimited)"
                    .into(),
            ));
        }

        match self.execution_mode {
            GraphQlExecutionMode::Proxy => {
                if !self.data_sources.is_empty() {
                    return Err(fail(
                        "`graphql.data_sources` requires `execution_mode: \"udg\"`".into(),
                    ));
                }
            }
            GraphQlExecutionMode::Udg => {
                if self.schema_sync.is_some() {
                    return Err(fail(
                        "`graphql.schema_sync` is not supported in `udg` execution mode — \
                         there is no single upstream to introspect (ADR-0010)"
                            .into(),
                    ));
                }
                if self.subscriptions.as_ref().is_some_and(|s| s.enabled) {
                    return Err(fail(
                        "`graphql.subscriptions` cannot be enabled in `udg` execution mode \
                         (ADR-0010)"
                            .into(),
                    ));
                }
                self.validate_data_sources(&schema, &fail)?;
            }
        }

        if let Some(playground) = &self.playground {
            validate_relative_path(&playground.path, "graphql.playground.path", &fail)?;
        }

        if let Some(sync) = &self.schema_sync {
            sync.validate(&fail)?;
        }

        if let Some(subs) = &self.subscriptions {
            if subs.max_message_bytes == Some(0) {
                return Err(fail(
                    "`graphql.subscriptions.max_message_bytes` must be greater than zero \
                     (omit it to inherit the API's request-body cap)"
                        .into(),
                ));
            }
            if subs.enabled && schema.schema_definition.subscription.is_none() {
                return Err(fail(
                    "`graphql.subscriptions` is enabled but `graphql.schema` defines no \
                     `Subscription` root type"
                        .into(),
                ));
            }
        }

        for (index, pq) in self.persisted_queries.iter().enumerate() {
            let doc = pq.validate(&schema, index, &fail)?;
            if self.execution_mode == GraphQlExecutionMode::Udg
                && doc
                    .operations
                    .get(pq.operation_name.as_deref())
                    .is_ok_and(|op| op.is_subscription())
            {
                return Err(fail(format!(
                    "`graphql.persisted_queries[{index}]` selects a subscription \
                     operation, which `udg` execution mode cannot execute"
                )));
            }
            if let Some(playground) = &self.playground {
                if pq.path == playground.path {
                    return Err(fail(format!(
                        "`graphql.persisted_queries[{index}].path` collides with the \
                         playground path `{}`",
                        playground.path
                    )));
                }
            }
        }
        Ok(())
    }

    /// Validates the UDG data-source map against the schema: every key must
    /// name a field of a root operation type, every root field must be
    /// mapped, and every source must be well-formed (ADR-0010).
    fn validate_data_sources(
        &self,
        schema: &apollo_compiler::validation::Valid<apollo_compiler::Schema>,
        fail: &impl Fn(String) -> Error,
    ) -> Result<(), Error> {
        if self.data_sources.is_empty() {
            return Err(fail(
                "`udg` execution mode requires `graphql.data_sources` (one entry per \
                 root field)"
                    .into(),
            ));
        }
        let roots: Vec<&str> = [
            schema.schema_definition.query.as_ref(),
            schema.schema_definition.mutation.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|component| component.name.as_str())
        .collect();

        for (key, source) in &self.data_sources {
            let Some((ty, field_name)) = key.split_once('.') else {
                return Err(fail(format!(
                    "`graphql.data_sources` key `{key}` must be `<RootType>.<field>` \
                     (e.g. `Query.user`)"
                )));
            };
            if !roots.contains(&ty) {
                return Err(fail(format!(
                    "`graphql.data_sources` key `{key}`: `{ty}` is not the schema's \
                     query or mutation root type"
                )));
            }
            let known = schema
                .get_object(ty)
                .is_some_and(|object| object.fields.contains_key(field_name));
            if !known {
                return Err(fail(format!(
                    "`graphql.data_sources` key `{key}`: type `{ty}` has no field \
                     `{field_name}`"
                )));
            }
            source.validate(key, fail)?;
        }

        for root in roots {
            let Some(object) = schema.get_object(root) else {
                continue;
            };
            for name in object.fields.keys() {
                let key = format!("{root}.{name}");
                if !self.data_sources.contains_key(&key) {
                    return Err(fail(format!(
                        "`graphql.data_sources` must map every root field in `udg` \
                         execution mode; missing `{key}`"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Checks a listen-path-relative path: `/`-prefixed, no query string or
/// fragment, no empty inner segments.
fn validate_relative_path(
    path: &str,
    field: &str,
    fail: &impl Fn(String) -> Error,
) -> Result<(), Error> {
    if !path.starts_with('/') {
        return Err(fail(format!("`{field}` must start with '/', got `{path}`")));
    }
    if path.contains('?') || path.contains('#') {
        return Err(fail(format!(
            "`{field}` must not contain a query string or fragment: `{path}`"
        )));
    }
    if path.len() > 1 && path.split('/').skip(1).any(str::is_empty) {
        return Err(fail(format!(
            "`{field}` must not contain empty segments: `{path}`"
        )));
    }
    Ok(())
}

impl PersistedQuery {
    /// Validates the entry, returning the parsed operation document (so
    /// mode-specific checks need not re-parse it).
    fn validate(
        &self,
        schema: &apollo_compiler::validation::Valid<apollo_compiler::Schema>,
        index: usize,
        fail: &impl Fn(String) -> Error,
    ) -> Result<apollo_compiler::validation::Valid<apollo_compiler::ExecutableDocument>, Error>
    {
        let field = |name: &str| format!("graphql.persisted_queries[{index}].{name}");

        if !TRANSFORM_METHODS
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&self.method))
        {
            return Err(fail(format!(
                "`{}` must be one of {} (got `{}`)",
                field("method"),
                TRANSFORM_METHODS.join(", "),
                self.method
            )));
        }

        validate_relative_path(&self.path, &field("path"), fail)?;
        let mut seen = Vec::new();
        for segment in self.path.split('/').skip(1) {
            let is_param = segment.starts_with('{') || segment.ends_with('}');
            if !is_param {
                continue;
            }
            let name = segment
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or_default();
            let valid_name = !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !name.starts_with(|c: char| c.is_ascii_digit());
            if !valid_name {
                return Err(fail(format!(
                    "`{}` parameter segment `{segment}` must be `{{name}}` with an \
                     alphanumeric/underscore name not starting with a digit",
                    field("path")
                )));
            }
            if seen.contains(&name) {
                return Err(fail(format!(
                    "`{}` declares parameter `{{{name}}}` more than once",
                    field("path")
                )));
            }
            seen.push(name);
        }

        let doc = apollo_compiler::ExecutableDocument::parse_and_validate(
            schema,
            &self.operation,
            "persisted.graphql",
        )
        .map_err(|e| {
            fail(format!(
                "`{}` is not valid against the schema: {}",
                field("operation"),
                diagnostic_reasons(&e.errors)
            ))
        })?;
        if doc.operations.get(self.operation_name.as_deref()).is_err() {
            return Err(fail(match &self.operation_name {
                Some(name) => format!(
                    "`{}` (`{name}`) does not name an operation in the document",
                    field("operation_name")
                ),
                None => format!(
                    "`{}` defines multiple operations; set `operation_name` to pick one",
                    field("operation")
                ),
            }));
        }

        if let Some(variables) = &self.variables {
            let Some(object) = variables.as_object() else {
                return Err(fail(format!(
                    "`{}` must be a JSON object",
                    field("variables")
                )));
            };
            validate_variable_template(object, &seen, &field("variables"), fail)?;
        }
        Ok(doc)
    }
}

/// Checks every `$path.<name>` reference in a variables template against
/// the declared path parameters (recursing into nested objects/arrays).
fn validate_variable_template(
    object: &serde_json::Map<String, serde_json::Value>,
    params: &[&str],
    field: &str,
    fail: &impl Fn(String) -> Error,
) -> Result<(), Error> {
    fn walk(
        value: &serde_json::Value,
        params: &[&str],
        field: &str,
        fail: &impl Fn(String) -> Error,
    ) -> Result<(), Error> {
        match value {
            serde_json::Value::String(s) => {
                if let Some(name) = s.strip_prefix("$path.") {
                    if !params.contains(&name) {
                        return Err(fail(format!(
                            "`{field}` references `$path.{name}` but the path declares no \
                             `{{{name}}}` parameter"
                        )));
                    }
                }
                Ok(())
            }
            serde_json::Value::Array(items) => {
                items.iter().try_for_each(|v| walk(v, params, field, fail))
            }
            serde_json::Value::Object(map) => {
                map.values().try_for_each(|v| walk(v, params, field, fail))
            }
            _ => Ok(()),
        }
    }
    object
        .values()
        .try_for_each(|v| walk(v, params, field, fail))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "type Query { hello: String user(id: ID!): User } \
                          type User { id: ID! name: String }";

    fn parse(json: &str) -> GraphQlConfig {
        serde_json::from_str(json).expect("valid graphql config JSON")
    }

    fn minimal() -> GraphQlConfig {
        parse(&serde_json::json!({ "schema": SCHEMA }).to_string())
    }

    #[test]
    fn minimal_config_gets_defaults_and_validates() {
        let cfg = minimal();
        assert!(cfg.enabled);
        assert_eq!(cfg.execution_mode, GraphQlExecutionMode::Proxy);
        assert!(cfg.introspection_enabled);
        assert!(cfg.max_query_depth.is_none());
        assert!(cfg.playground.is_none());
        assert!(cfg.persisted_queries.is_empty());
        cfg.validate("api").expect("valid");
    }

    #[test]
    fn full_config_round_trips_and_optionals_stay_off_the_wire() {
        let cfg = parse(
            &serde_json::json!({
                "schema": SCHEMA,
                "enabled": false,
                "introspection_enabled": false,
                "max_query_depth": 5,
                "playground": {},
                "persisted_queries": [{
                    "method": "GET",
                    "path": "/users/{id}",
                    "operation": "query User($id: ID!) { user(id: $id) { name } }",
                    "variables": { "id": "$path.id" }
                }]
            })
            .to_string(),
        );
        cfg.validate("api").expect("valid");
        assert_eq!(
            cfg.playground.as_ref().expect("set").path,
            DEFAULT_PLAYGROUND_PATH
        );
        let json = serde_json::to_string(&cfg).expect("serializes");
        assert_eq!(parse(&json), cfg);

        let bare = serde_json::to_string(&minimal()).expect("serializes");
        for field in ["max_query_depth", "playground", "persisted_queries"] {
            assert!(!bare.contains(field), "`{field}` serialized when unset");
        }
    }

    #[test]
    fn broken_schemas_are_rejected() {
        for (label, schema) in [
            ("empty", ""),
            ("whitespace", "  "),
            ("syntax error", "type Query {"),
            ("unknown type reference", "type Query { user: Missing }"),
            ("no query root", "type User { id: ID! }"),
        ] {
            let mut cfg = minimal();
            cfg.schema = schema.into();
            let err = cfg.validate("api").unwrap_err().to_string();
            assert!(err.contains("graphql.schema"), "{label}: got {err}");
        }
    }

    #[test]
    fn config_is_validated_even_when_disabled() {
        let mut cfg = minimal();
        cfg.enabled = false;
        cfg.schema = "type Query {".into();
        assert!(cfg.validate("api").is_err());
    }

    #[test]
    fn zero_depth_is_rejected() {
        let mut cfg = minimal();
        cfg.max_query_depth = Some(0);
        let err = cfg.validate("api").unwrap_err().to_string();
        assert!(err.contains("max_query_depth"), "got: {err}");
    }

    #[test]
    fn playground_path_rules_are_enforced() {
        for bad in ["playground", "/play?x=1", "/play#frag", "/a//b"] {
            let mut cfg = minimal();
            cfg.playground = Some(PlaygroundConfig { path: bad.into() });
            assert!(cfg.validate("api").is_err(), "path `{bad}` accepted");
        }
    }

    fn persisted(json: serde_json::Value) -> GraphQlConfig {
        parse(
            &serde_json::json!({
                "schema": SCHEMA,
                "persisted_queries": [json]
            })
            .to_string(),
        )
    }

    #[test]
    fn persisted_query_rules_are_enforced() {
        // A valid one passes.
        persisted(serde_json::json!({
            "method": "get",
            "path": "/users/{id}",
            "operation": "query User($id: ID!) { user(id: $id) { name } }",
            "variables": { "id": "$path.id", "trace": "$header.x-trace-id" }
        }))
        .validate("api")
        .expect("valid");

        let cases = [
            (
                "method",
                serde_json::json!({
                    "method": "CONNECT", "path": "/x", "operation": "{ hello }"
                }),
            ),
            (
                "path",
                serde_json::json!({
                    "method": "GET", "path": "no-slash", "operation": "{ hello }"
                }),
            ),
            (
                "parameter segment",
                serde_json::json!({
                    "method": "GET", "path": "/users/{1bad}", "operation": "{ hello }"
                }),
            ),
            (
                "parameter segment",
                serde_json::json!({
                    "method": "GET", "path": "/users/{}", "operation": "{ hello }"
                }),
            ),
            (
                "more than once",
                serde_json::json!({
                    "method": "GET", "path": "/{id}/{id}", "operation": "{ hello }"
                }),
            ),
            (
                "operation",
                serde_json::json!({
                    "method": "GET", "path": "/x", "operation": "{ missingField }"
                }),
            ),
            (
                "operation_name",
                serde_json::json!({
                    "method": "GET", "path": "/x", "operation": "query A { hello }",
                    "operation_name": "B"
                }),
            ),
            (
                "multiple operations",
                serde_json::json!({
                    "method": "GET", "path": "/x",
                    "operation": "query A { hello } query B { hello }"
                }),
            ),
            (
                "variables",
                serde_json::json!({
                    "method": "GET", "path": "/x", "operation": "{ hello }",
                    "variables": [1, 2]
                }),
            ),
            (
                "$path.missing",
                serde_json::json!({
                    "method": "GET", "path": "/x", "operation": "{ hello }",
                    "variables": { "id": "$path.missing" }
                }),
            ),
        ];
        for (label, pq) in cases {
            let err = persisted(pq).validate("api").unwrap_err().to_string();
            assert!(
                err.contains("persisted_queries[0]"),
                "{label}: err should name the entry, got {err}"
            );
        }
    }

    #[test]
    fn nested_variable_templates_are_checked() {
        let cfg = persisted(serde_json::json!({
            "method": "POST", "path": "/orders/{id}",
            "operation": "{ hello }",
            "variables": { "filter": { "ids": ["$path.id", "$path.nope"] } }
        }));
        let err = cfg.validate("api").unwrap_err().to_string();
        assert!(err.contains("$path.nope"), "got: {err}");
    }

    #[test]
    fn persisted_path_must_not_collide_with_the_playground() {
        let mut cfg = persisted(serde_json::json!({
            "method": "GET", "path": "/playground", "operation": "{ hello }"
        }));
        cfg.playground = Some(PlaygroundConfig::default());
        let err = cfg.validate("api").unwrap_err().to_string();
        assert!(err.contains("collides"), "got: {err}");
    }

    #[test]
    fn path_template_params_extracts_names_in_order() {
        assert_eq!(
            path_template_params("/users/{id}/posts/{post_id}"),
            vec!["id", "post_id"]
        );
        assert!(path_template_params("/plain/path").is_empty());
    }

    #[test]
    fn schema_sync_defaults_and_round_trip() {
        let cfg = parse(
            &serde_json::json!({
                "schema": SCHEMA,
                "schema_sync": {}
            })
            .to_string(),
        );
        cfg.validate("api").expect("valid");
        let sync = cfg.schema_sync.as_ref().expect("set");
        assert_eq!(sync.interval_ms, DEFAULT_SCHEMA_SYNC_INTERVAL_MS);
        assert_eq!(sync.timeout_ms, DEFAULT_SCHEMA_SYNC_TIMEOUT_MS);
        assert!(sync.url.is_none());
        assert!(sync.headers.is_empty());

        let full = parse(
            &serde_json::json!({
                "schema": SCHEMA,
                "schema_sync": {
                    "interval_ms": 5000,
                    "timeout_ms": 2000,
                    "url": "https://internal.example/graphql",
                    "headers": { "authorization": "Bearer t" }
                }
            })
            .to_string(),
        );
        full.validate("api").expect("valid");
        let json = serde_json::to_string(&full).expect("serializes");
        assert_eq!(parse(&json), full);

        // Unset stays off the wire.
        let bare = serde_json::to_string(&minimal()).expect("serializes");
        assert!(!bare.contains("schema_sync"));
    }

    #[test]
    fn schema_sync_rules_are_enforced() {
        let cases = [
            ("interval_ms", serde_json::json!({ "interval_ms": 0 })),
            ("timeout_ms", serde_json::json!({ "timeout_ms": 0 })),
            ("url", serde_json::json!({ "url": "ftp://x/graphql" })),
            ("url", serde_json::json!({ "url": "/relative" })),
            ("url", serde_json::json!({ "url": "http://bad host/" })),
            (
                "header name",
                serde_json::json!({ "headers": { "bad name": "v" } }),
            ),
            (
                "hop-by-hop",
                serde_json::json!({ "headers": { "Connection": "close" } }),
            ),
            (
                "header value",
                serde_json::json!({ "headers": { "x-ok": "bad\nvalue" } }),
            ),
        ];
        for (label, sync) in cases {
            let cfg =
                parse(&serde_json::json!({ "schema": SCHEMA, "schema_sync": sync }).to_string());
            let err = cfg.validate("api").unwrap_err().to_string();
            assert!(
                err.contains("schema_sync"),
                "{label}: err should name schema_sync, got {err}"
            );
        }
    }

    const SUB_SCHEMA: &str = "type Query { hello: String } \
                              type Subscription { ticks: Int }";

    #[test]
    fn subscriptions_defaults_and_round_trip() {
        let cfg = parse(
            &serde_json::json!({
                "schema": SUB_SCHEMA,
                "subscriptions": {}
            })
            .to_string(),
        );
        cfg.validate("api").expect("valid");
        let subs = cfg.subscriptions.as_ref().expect("set");
        assert!(subs.enabled);
        assert!(subs.max_message_bytes.is_none());
        assert_eq!(*subs, SubscriptionsConfig::default());

        let full = parse(
            &serde_json::json!({
                "schema": SUB_SCHEMA,
                "subscriptions": { "enabled": true, "max_message_bytes": 4096 }
            })
            .to_string(),
        );
        full.validate("api").expect("valid");
        let json = serde_json::to_string(&full).expect("serializes");
        assert_eq!(parse(&json), full);

        // Unset stays off the wire.
        let bare = serde_json::to_string(&minimal()).expect("serializes");
        assert!(!bare.contains("subscriptions"));
    }

    #[test]
    fn subscriptions_zero_message_cap_is_rejected() {
        let cfg = parse(
            &serde_json::json!({
                "schema": SUB_SCHEMA,
                "subscriptions": { "max_message_bytes": 0 }
            })
            .to_string(),
        );
        let err = cfg.validate("api").unwrap_err().to_string();
        assert!(err.contains("max_message_bytes"), "got: {err}");
    }

    #[test]
    fn subscriptions_require_a_subscription_root() {
        let cfg = parse(
            &serde_json::json!({
                "schema": SCHEMA,
                "subscriptions": {}
            })
            .to_string(),
        );
        let err = cfg.validate("api").unwrap_err().to_string();
        assert!(err.contains("Subscription"), "got: {err}");

        // A disabled block on a subscription-less schema is fine (the kill
        // switch parks the config without forcing a schema change).
        let off = parse(
            &serde_json::json!({
                "schema": SCHEMA,
                "subscriptions": { "enabled": false }
            })
            .to_string(),
        );
        off.validate("api").expect("valid when disabled");
    }

    #[test]
    fn execution_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&GraphQlExecutionMode::Proxy).expect("serializes"),
            r#""proxy""#
        );
        assert_eq!(
            serde_json::to_string(&GraphQlExecutionMode::Udg).expect("serializes"),
            r#""udg""#
        );
    }

    const UDG_SCHEMA: &str = "type Query { hello: String user(id: ID!): User } \
                              type Mutation { rename(id: ID!, name: String!): User } \
                              type User { id: ID! name: String }";

    fn udg_sources() -> serde_json::Value {
        serde_json::json!({
            "Query.hello": { "kind": "rest", "url": "http://up.internal/hello" },
            "Query.user": {
                "kind": "rest",
                "url": "http://up.internal/users/{{ args.id }}",
                "headers": { "x-caller": "{{ _g2.session.alias }}" }
            },
            "Mutation.rename": {
                "kind": "graphql",
                "url": "http://gql.internal/graphql",
                "headers": { "authorization": "Bearer t" }
            }
        })
    }

    fn udg(mutator: impl FnOnce(&mut serde_json::Value)) -> GraphQlConfig {
        let mut json = serde_json::json!({
            "schema": UDG_SCHEMA,
            "execution_mode": "udg",
            "data_sources": udg_sources()
        });
        mutator(&mut json);
        parse(&json.to_string())
    }

    #[test]
    fn udg_config_round_trips_and_validates() {
        let cfg = udg(|_| {});
        cfg.validate("api").expect("valid");
        assert_eq!(cfg.execution_mode, GraphQlExecutionMode::Udg);
        assert_eq!(cfg.data_sources.len(), 3);
        let json = serde_json::to_string(&cfg).expect("serializes");
        assert_eq!(parse(&json), cfg);

        // Unset stays off the wire, and REST defaults apply.
        let bare = serde_json::to_string(&minimal()).expect("serializes");
        assert!(!bare.contains("data_sources"));
        let UdgDataSource::Rest(rest) = &cfg.data_sources["Query.hello"] else {
            panic!("expected a rest source");
        };
        assert_eq!(rest.method, "GET");
        assert!(rest.body.is_none() && rest.timeout_ms.is_none());
    }

    #[test]
    fn proxy_mode_rejects_data_sources() {
        let cfg = udg(|json| {
            json["execution_mode"] = "proxy".into();
        });
        let err = cfg.validate("api").unwrap_err().to_string();
        assert!(
            err.contains("requires `execution_mode: \"udg\"`"),
            "got: {err}"
        );
    }

    #[test]
    fn udg_requires_data_sources_and_full_coverage() {
        let empty = udg(|json| {
            json["data_sources"] = serde_json::json!({});
        });
        let err = empty.validate("api").unwrap_err().to_string();
        assert!(
            err.contains("requires `graphql.data_sources`"),
            "got: {err}"
        );

        let partial = udg(|json| {
            json["data_sources"]
                .as_object_mut()
                .expect("object")
                .remove("Query.user");
        });
        let err = partial.validate("api").unwrap_err().to_string();
        assert!(err.contains("missing `Query.user`"), "got: {err}");
    }

    #[test]
    fn udg_rejects_schema_sync_and_enabled_subscriptions() {
        let sync = udg(|json| {
            json["schema_sync"] = serde_json::json!({});
        });
        let err = sync.validate("api").unwrap_err().to_string();
        assert!(err.contains("schema_sync"), "got: {err}");

        let subs = udg(|json| {
            json["schema"] = format!("{UDG_SCHEMA} type Subscription {{ ticks: Int }}").into();
            json["subscriptions"] = serde_json::json!({});
        });
        let err = subs.validate("api").unwrap_err().to_string();
        assert!(err.contains("subscriptions"), "got: {err}");

        // A disabled block stays parkable (ADR-0010).
        let off = udg(|json| {
            json["schema"] = format!("{UDG_SCHEMA} type Subscription {{ ticks: Int }}").into();
            json["subscriptions"] = serde_json::json!({ "enabled": false });
        });
        off.validate("api").expect("valid when disabled");
    }

    #[test]
    fn udg_data_source_rules_are_enforced() {
        let cases = [
            (
                "must be `<RootType>.<field>`",
                "nodot",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/"
                }),
            ),
            (
                "not the schema's query or mutation root type",
                "User.name",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/"
                }),
            ),
            (
                "has no field",
                "Query.missing",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/"
                }),
            ),
            (
                "method",
                "Query.hello",
                serde_json::json!({
                    "kind": "rest", "method": "CONNECT", "url": "http://x/"
                }),
            ),
            (
                "url",
                "Query.hello",
                serde_json::json!({
                    "kind": "rest", "url": " "
                }),
            ),
            (
                "minijinja",
                "Query.hello",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/{{ broken"
                }),
            ),
            (
                "minijinja",
                "Query.hello",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/", "body": "{% bad %}"
                }),
            ),
            (
                "header name",
                "Query.hello",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/", "headers": { "bad name": "v" }
                }),
            ),
            (
                "hop-by-hop",
                "Query.hello",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/", "headers": { "Connection": "close" }
                }),
            ),
            (
                "minijinja",
                "Query.hello",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/", "headers": { "x-ok": "{{ broken" }
                }),
            ),
            (
                "timeout_ms",
                "Query.hello",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/", "timeout_ms": 0
                }),
            ),
            (
                "max_response_bytes",
                "Query.hello",
                serde_json::json!({
                    "kind": "rest", "url": "http://x/", "max_response_bytes": 0
                }),
            ),
            (
                "absolute http(s) URL",
                "Query.hello",
                serde_json::json!({
                    "kind": "graphql", "url": "ftp://x/graphql"
                }),
            ),
            (
                "absolute http(s) URL",
                "Query.hello",
                serde_json::json!({
                    "kind": "graphql", "url": "/relative"
                }),
            ),
        ];
        for (needle, key, source) in cases {
            let cfg = udg(|json| {
                json["data_sources"][key] = source.clone();
            });
            let err = cfg.validate("api").unwrap_err().to_string();
            assert!(
                err.contains(needle),
                "key `{key}`: expected `{needle}` in: {err}"
            );
        }
    }

    #[test]
    fn udg_rejects_persisted_subscriptions() {
        let cfg = udg(|json| {
            json["schema"] = format!("{UDG_SCHEMA} type Subscription {{ ticks: Int }}").into();
            json["persisted_queries"] = serde_json::json!([{
                "method": "GET", "path": "/ticks",
                "operation": "subscription { ticks }"
            }]);
        });
        let err = cfg.validate("api").unwrap_err().to_string();
        assert!(err.contains("subscription operation"), "got: {err}");
    }
}
