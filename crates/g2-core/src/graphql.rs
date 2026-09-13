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

use serde::{Deserialize, Serialize};

use crate::transform::TRANSFORM_METHODS;
use crate::Error;

/// Playground path used when a [`PlaygroundConfig`] does not name one,
/// relative to the API's listen path.
pub const DEFAULT_PLAYGROUND_PATH: &str = "/playground";

fn default_playground_path() -> String {
    DEFAULT_PLAYGROUND_PATH.to_owned()
}

fn default_true() -> bool {
    true
}

/// How the gateway executes GraphQL for an API.
///
/// Only [`Proxy`](Self::Proxy) exists today; the enum is the extension
/// point for later M9 modes (UDG, federation
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
    /// or persisted path breaks the path rules, or a persisted query has an
    /// invalid method, path template, operation, operation name, or
    /// variables template.
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

        if let Some(playground) = &self.playground {
            validate_relative_path(&playground.path, "graphql.playground.path", &fail)?;
        }

        for (index, pq) in self.persisted_queries.iter().enumerate() {
            pq.validate(&schema, index, &fail)?;
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
    fn validate(
        &self,
        schema: &apollo_compiler::validation::Valid<apollo_compiler::Schema>,
        index: usize,
        fail: &impl Fn(String) -> Error,
    ) -> Result<(), Error> {
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
        Ok(())
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
    fn execution_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&GraphQlExecutionMode::Proxy).expect("serializes"),
            r#""proxy""#
        );
    }
}
