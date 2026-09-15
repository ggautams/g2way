//! GraphQL schema sync from upstream introspection (milestone M9,
//! ADR-0008).
//!
//! Three pieces live here:
//!
//! 1. [`INTROSPECTION_QUERY`] — the introspection document a sync task
//!    POSTs to the upstream.
//! 2. [`introspection_to_sdl`] — a pure converter from the introspection
//!    JSON response to SDL text. apollo-compiler serializes schemas but
//!    cannot *import* introspection JSON, so the conversion is hand-written
//!    here; the produced SDL then goes through the exact
//!    `Schema::parse_and_validate` path config validation uses, keeping a
//!    single validation entry point (ADR-0008).
//! 3. [`GraphQlSyncHandle`] — the handle a refresher task drives one API's
//!    sync through: fetch scheduling ([`SyncNudge::wait_interval`],
//!    [`trigger`][`GraphQlSyncHandle::trigger`]), applying a response
//!    ([`apply_introspection`][`GraphQlSyncHandle::apply_introspection`]),
//!    and status for the dashboard.
//!
//! The sync itself is **pod-local and stale-on-error**: a successful fetch
//! swaps the compiled schema (and the persisted operations re-validated
//! against it) behind the layer's `ArcSwap`; any failure — transport,
//! non-2xx, bad JSON, SDL that does not compile, a persisted query invalid
//! against the new schema — keeps the previous schema serving and records
//! the error. The HTTP fetching lives in `g2-proxy` (this crate carries no
//! client, matching the JWKS inversion).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apollo_compiler::{ExecutableDocument, Schema};
use arc_swap::ArcSwapOption;
use g2_core::graphql::SchemaSyncConfig;
use serde::Deserialize;
use tokio::sync::Notify;

use crate::graphql::{diagnostic_messages, GraphQlSchemaState, GraphQlShared};

/// The introspection document a sync task sends upstream: the canonical
/// graphql-js query (descriptions, deprecated members included, argument
/// default values, directive declarations) minus `specifiedByURL` and
/// `isRepeatable`, which older servers reject (deliberate v1 compatibility
/// trade-off, ADR-0008).
pub const INTROSPECTION_QUERY: &str = r#"query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"#;

/// Scalars every GraphQL implementation predefines; redeclaring them in
/// SDL is at best noise and at worst a validation error.
const BUILTIN_SCALARS: [&str; 5] = ["Int", "Float", "String", "Boolean", "ID"];

/// Directives apollo-compiler predefines; redeclaring them fails schema
/// validation.
const BUILTIN_DIRECTIVES: [&str; 4] = ["skip", "include", "deprecated", "specifiedBy"];

// Serde mirrors of the introspection response, tolerant of absent
// optionals (older servers omit fields newer ones return).

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntrospectionSchema {
    query_type: Option<NamedTypeRef>,
    mutation_type: Option<NamedTypeRef>,
    subscription_type: Option<NamedTypeRef>,
    types: Vec<IntrospectionType>,
    #[serde(default)]
    directives: Vec<IntrospectionDirective>,
}

#[derive(Deserialize)]
struct NamedTypeRef {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntrospectionType {
    kind: String,
    name: Option<String>,
    description: Option<String>,
    fields: Option<Vec<IntrospectionField>>,
    interfaces: Option<Vec<TypeRef>>,
    possible_types: Option<Vec<TypeRef>>,
    enum_values: Option<Vec<IntrospectionEnumValue>>,
    input_fields: Option<Vec<IntrospectionInputValue>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntrospectionField {
    name: String,
    description: Option<String>,
    #[serde(default)]
    args: Vec<IntrospectionInputValue>,
    #[serde(rename = "type")]
    ty: TypeRef,
    #[serde(default)]
    is_deprecated: bool,
    deprecation_reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntrospectionInputValue {
    name: String,
    #[serde(rename = "type")]
    ty: TypeRef,
    default_value: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntrospectionEnumValue {
    name: String,
    description: Option<String>,
    #[serde(default)]
    is_deprecated: bool,
    deprecation_reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntrospectionDirective {
    name: String,
    description: Option<String>,
    #[serde(default)]
    locations: Vec<String>,
    #[serde(default)]
    args: Vec<IntrospectionInputValue>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TypeRef {
    kind: String,
    name: Option<String>,
    of_type: Option<Box<TypeRef>>,
}

/// Converts a GraphQL introspection response to SDL text.
///
/// Accepts the full HTTP envelope (`{"data": {"__schema": …}}`) or a bare
/// `{"__schema": …}` object. Built-in types (`__`-prefixed), built-in
/// scalars, and built-in directives are skipped — implementations
/// predefine them and redeclarations fail validation. Argument default
/// values are emitted verbatim (introspection already returns GraphQL
/// literal syntax); type, field, and enum-value descriptions become block
/// strings; argument descriptions are dropped (a documentation-only loss —
/// validation is unaffected; ADR-0008).
///
/// The output is **not** validated here: callers compile it with
/// `Schema::parse_and_validate`, so a converter gap fails safe (the sync
/// keeps the previous schema) rather than producing a broken schema.
///
/// # Errors
///
/// Returns a one-line reason when the response carries no `__schema`
/// (including an introspection-disabled upstream's `errors` reply), does
/// not match the introspection shape, or contains an unrenderable
/// construct (e.g. a wrapper-type chain with no named type).
pub fn introspection_to_sdl(response: &serde_json::Value) -> Result<String, String> {
    let schema_json = response
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| response.get("__schema"))
        .ok_or_else(|| match first_graphql_error(response) {
            Some(msg) => format!("introspection failed upstream: {msg}"),
            None => "response has no `__schema` (introspection disabled upstream?)".to_owned(),
        })?;
    let schema: IntrospectionSchema = serde_json::from_value(schema_json.clone())
        .map_err(|e| format!("response does not match the introspection shape: {e}"))?;
    render_schema(&schema)
}

/// The first `errors[].message` of a GraphQL response, if any.
fn first_graphql_error(response: &serde_json::Value) -> Option<&str> {
    response
        .get("errors")?
        .as_array()?
        .first()?
        .get("message")?
        .as_str()
}

fn render_schema(schema: &IntrospectionSchema) -> Result<String, String> {
    let query_root = schema
        .query_type
        .as_ref()
        .ok_or("introspection reports no query root type")?;

    let mut out = String::new();
    out.push_str("schema {\n");
    out.push_str(&format!("  query: {}\n", query_root.name));
    if let Some(m) = &schema.mutation_type {
        out.push_str(&format!("  mutation: {}\n", m.name));
    }
    if let Some(s) = &schema.subscription_type {
        out.push_str(&format!("  subscription: {}\n", s.name));
    }
    out.push_str("}\n");

    for directive in &schema.directives {
        if BUILTIN_DIRECTIVES.contains(&directive.name.as_str()) {
            continue;
        }
        if directive.locations.is_empty() {
            return Err(format!(
                "directive `@{}` reports no locations",
                directive.name
            ));
        }
        out.push('\n');
        push_description(&mut out, directive.description.as_deref(), "");
        out.push_str(&format!(
            "directive @{}{} on {}\n",
            directive.name,
            render_args(&directive.args)?,
            directive.locations.join(" | ")
        ));
    }

    for ty in &schema.types {
        let Some(name) = ty.name.as_deref() else {
            return Err("a schema type has no name".to_owned());
        };
        if name.starts_with("__") {
            continue;
        }
        match ty.kind.as_str() {
            "SCALAR" if BUILTIN_SCALARS.contains(&name) => {}
            "SCALAR" => {
                out.push('\n');
                push_description(&mut out, ty.description.as_deref(), "");
                out.push_str(&format!("scalar {name}\n"));
            }
            kind @ ("OBJECT" | "INTERFACE") => {
                let keyword = if kind == "OBJECT" {
                    "type"
                } else {
                    "interface"
                };
                out.push('\n');
                push_description(&mut out, ty.description.as_deref(), "");
                out.push_str(&format!("{keyword} {name}"));
                let interfaces = ty.interfaces.as_deref().unwrap_or_default();
                if !interfaces.is_empty() {
                    let names = interfaces
                        .iter()
                        .map(named_type)
                        .collect::<Result<Vec<_>, _>>()?;
                    out.push_str(&format!(" implements {}", names.join(" & ")));
                }
                let fields = ty.fields.as_deref().unwrap_or_default();
                if fields.is_empty() {
                    out.push('\n');
                } else {
                    out.push_str(" {\n");
                    for field in fields {
                        push_description(&mut out, field.description.as_deref(), "  ");
                        out.push_str(&format!(
                            "  {}{}: {}{}\n",
                            field.name,
                            render_args(&field.args)?,
                            render_type_ref(&field.ty)?,
                            render_deprecation(
                                field.is_deprecated,
                                field.deprecation_reason.as_deref()
                            ),
                        ));
                    }
                    out.push_str("}\n");
                }
            }
            "UNION" => {
                out.push('\n');
                push_description(&mut out, ty.description.as_deref(), "");
                let members = ty.possible_types.as_deref().unwrap_or_default();
                if members.is_empty() {
                    return Err(format!("union `{name}` reports no member types"));
                }
                let names = members
                    .iter()
                    .map(named_type)
                    .collect::<Result<Vec<_>, _>>()?;
                out.push_str(&format!("union {name} = {}\n", names.join(" | ")));
            }
            "ENUM" => {
                out.push('\n');
                push_description(&mut out, ty.description.as_deref(), "");
                out.push_str(&format!("enum {name} {{\n"));
                for value in ty.enum_values.as_deref().unwrap_or_default() {
                    push_description(&mut out, value.description.as_deref(), "  ");
                    out.push_str(&format!(
                        "  {}{}\n",
                        value.name,
                        render_deprecation(
                            value.is_deprecated,
                            value.deprecation_reason.as_deref()
                        ),
                    ));
                }
                out.push_str("}\n");
            }
            "INPUT_OBJECT" => {
                out.push('\n');
                push_description(&mut out, ty.description.as_deref(), "");
                out.push_str(&format!("input {name} {{\n"));
                for field in ty.input_fields.as_deref().unwrap_or_default() {
                    out.push_str(&format!("  {}\n", render_input_value(field)?));
                }
                out.push_str("}\n");
            }
            other => return Err(format!("type `{name}` has unknown kind `{other}`")),
        }
    }
    Ok(out)
}

/// Renders a parenthesized argument list, or nothing when there are no
/// arguments.
fn render_args(args: &[IntrospectionInputValue]) -> Result<String, String> {
    if args.is_empty() {
        return Ok(String::new());
    }
    let rendered = args
        .iter()
        .map(render_input_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!("({})", rendered.join(", ")))
}

/// Renders `name: Type` with the verbatim default value, if any.
fn render_input_value(value: &IntrospectionInputValue) -> Result<String, String> {
    let mut out = format!("{}: {}", value.name, render_type_ref(&value.ty)?);
    if let Some(default) = &value.default_value {
        out.push_str(&format!(" = {default}"));
    }
    Ok(out)
}

/// Renders a (possibly wrapped) type reference: `NON_NULL` → `T!`,
/// `LIST` → `[T]`, otherwise the named type.
fn render_type_ref(ty: &TypeRef) -> Result<String, String> {
    match ty.kind.as_str() {
        "NON_NULL" => {
            let inner = ty
                .of_type
                .as_deref()
                .ok_or("a NON_NULL type reference has no inner type")?;
            Ok(format!("{}!", render_type_ref(inner)?))
        }
        "LIST" => {
            let inner = ty
                .of_type
                .as_deref()
                .ok_or("a LIST type reference has no inner type")?;
            Ok(format!("[{}]", render_type_ref(inner)?))
        }
        _ => ty
            .name
            .clone()
            .ok_or_else(|| "a type reference has no name".to_owned()),
    }
}

/// The name of a type reference that must be a plain named type
/// (`implements` and union member lists).
fn named_type(ty: &TypeRef) -> Result<&str, String> {
    ty.name
        .as_deref()
        .ok_or_else(|| "a type reference has no name".to_owned())
}

/// Renders ` @deprecated` / ` @deprecated(reason: "…")`, or nothing.
fn render_deprecation(is_deprecated: bool, reason: Option<&str>) -> String {
    if !is_deprecated {
        return String::new();
    }
    match reason {
        Some(reason) => format!(" @deprecated(reason: {})", quote_string(reason)),
        None => " @deprecated".to_owned(),
    }
}

/// Appends a description as a block string (own lines, `indent`-prefixed),
/// escaping `"""` occurrences. The closing quotes get their own line, so a
/// description ending in `"` cannot merge into the terminator.
fn push_description(out: &mut String, description: Option<&str>, indent: &str) {
    let Some(description) = description else {
        return;
    };
    if description.is_empty() {
        return;
    }
    out.push_str(indent);
    out.push_str("\"\"\"\n");
    for line in description.split('\n') {
        out.push_str(indent);
        out.push_str(&line.replace("\"\"\"", "\\\"\"\""));
        out.push('\n');
    }
    out.push_str(indent);
    out.push_str("\"\"\"\n");
}

/// Quotes a GraphQL single-line string literal. JSON string escaping is a
/// valid subset of GraphQL's, so the JSON serializer does the work.
fn quote_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}

/// Sync status and trigger state for one API, owned by the layer's shared
/// state.
pub(crate) struct SchemaSync {
    pub(crate) config: SchemaSyncConfig,
    /// Unix seconds of the last successful sync; 0 = never.
    last_success_secs: AtomicU64,
    /// The most recent failure, cleared by the next success.
    last_error: ArcSwapOption<String>,
    /// Admin-trigger wakeup. `notify_one` stores a permit when no fetch
    /// loop is waiting, so concurrent nudges coalesce into one refetch.
    /// `Arc` so a refresher can wait on it *detached* — without keeping the
    /// whole layer state alive across an interval after a reload.
    nudge: Arc<Notify>,
}

impl SchemaSync {
    pub(crate) fn new(config: SchemaSyncConfig) -> Self {
        Self {
            config,
            last_success_secs: AtomicU64::new(0),
            last_error: ArcSwapOption::const_empty(),
            nudge: Arc::new(Notify::new()),
        }
    }
}

/// A wakeup listener detached from the layer state: a refresher waits on
/// this between fetches, so a dropped route table is not kept alive for an
/// extra interval by the waiting task.
#[derive(Debug, Clone)]
pub struct SyncNudge(Arc<Notify>);

impl SyncNudge {
    /// Waits until `interval` elapses or
    /// [`GraphQlSyncHandle::trigger`] fires (a trigger that arrived while
    /// nobody waited is consumed immediately), whichever comes first.
    pub async fn wait_interval(&self, interval: Duration) {
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            () = self.0.notified() => {}
        }
    }
}

/// A point-in-time view of one API's schema-sync state, surfaced on
/// `GET /g2/node`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaSyncSnapshot {
    /// Unix seconds of the last successful sync; `None` = never succeeded.
    pub last_success_unix_secs: Option<u64>,
    /// The most recent failure, `None` after a success.
    pub last_error: Option<String>,
}

/// Handle a refresher task drives one API's schema sync through.
///
/// Holds the layer's shared state strongly; obtain it from
/// [`GraphQlLayer::sync_handle`](crate::GraphQlLayer::sync_handle) and
/// [`downgrade`](Self::downgrade) it inside long-lived tasks so a dropped
/// route table ends them.
#[derive(Clone)]
pub struct GraphQlSyncHandle {
    pub(crate) shared: Arc<GraphQlShared>,
}

impl std::fmt::Debug for GraphQlSyncHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphQlSyncHandle")
            .field("api_id", &self.shared.api_id)
            .finish_non_exhaustive()
    }
}

/// Weak counterpart of [`GraphQlSyncHandle`]; a refresher task's loop
/// condition.
#[derive(Debug, Clone)]
pub struct WeakGraphQlSync {
    shared: Weak<GraphQlShared>,
}

impl WeakGraphQlSync {
    /// Upgrades back to a strong handle; `None` once the route (and its
    /// chain) has been dropped.
    #[must_use]
    pub fn upgrade(&self) -> Option<GraphQlSyncHandle> {
        self.shared
            .upgrade()
            .map(|shared| GraphQlSyncHandle { shared })
    }
}

impl GraphQlSyncHandle {
    fn sync(&self) -> &SchemaSync {
        self.shared
            .sync
            .as_ref()
            .expect("a GraphQlSyncHandle exists only for a layer with schema_sync configured")
    }

    /// The API id this handle syncs, for log lines.
    #[must_use]
    pub fn api_id(&self) -> &str {
        &self.shared.api_id
    }

    /// The sync configuration.
    #[must_use]
    pub fn config(&self) -> &SchemaSyncConfig {
        &self.sync().config
    }

    /// Requests an immediate re-fetch: wakes a [`SyncNudge`] waiter, or
    /// stores a permit consumed by the next wait. Concurrent triggers
    /// coalesce.
    pub fn trigger(&self) {
        self.sync().nudge.notify_one();
    }

    /// The detached wakeup a refresher waits on between fetches.
    #[must_use]
    pub fn nudge(&self) -> SyncNudge {
        SyncNudge(Arc::clone(&self.sync().nudge))
    }

    /// Records a failed sync attempt (kept until the next success).
    pub fn record_error(&self, error: String) {
        self.sync().last_error.store(Some(Arc::new(error)));
    }

    /// The current sync status.
    #[must_use]
    pub fn status(&self) -> SchemaSyncSnapshot {
        let sync = self.sync();
        let secs = sync.last_success_secs.load(Ordering::Relaxed);
        SchemaSyncSnapshot {
            last_success_unix_secs: (secs > 0).then_some(secs),
            last_error: sync.last_error.load_full().map(|e| (*e).clone()),
        }
    }

    /// Downgrades to a weak handle for a long-lived task.
    #[must_use]
    pub fn downgrade(&self) -> WeakGraphQlSync {
        WeakGraphQlSync {
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// Applies an introspection response: converts it to SDL, compiles the
    /// schema, re-validates every persisted operation against it, and swaps
    /// the layer's schema state. `Ok(true)` = swapped; `Ok(false)` = the
    /// SDL is unchanged (state untouched). Both record a success.
    ///
    /// # Errors
    ///
    /// Returns a one-line reason when the response cannot be converted, the
    /// SDL does not compile, or a persisted operation is invalid against
    /// the new schema — the previous state keeps serving in every case
    /// (stale-on-error; the caller records the error).
    pub fn apply_introspection(&self, response: &serde_json::Value) -> Result<bool, String> {
        let sdl = introspection_to_sdl(response)?;
        if self.shared.state.load().sdl == sdl {
            self.record_success();
            return Ok(false);
        }
        let schema = Schema::parse_and_validate(&sdl, "introspection.graphql").map_err(|e| {
            format!(
                "the introspected schema does not compile: {}",
                diagnostic_messages(&e.errors).join("; ")
            )
        })?;
        let mut persisted_docs = Vec::with_capacity(self.shared.persisted.len());
        for (index, p) in self.shared.persisted.iter().enumerate() {
            let doc =
                ExecutableDocument::parse_and_validate(&schema, &p.query, "persisted.graphql")
                    .map_err(|e| {
                        format!(
                            "persisted query [{index}] is not valid against the introspected \
                             schema: {}",
                            diagnostic_messages(&e.errors).join("; ")
                        )
                    })?;
            persisted_docs.push(doc);
        }
        self.shared.state.store(Arc::new(GraphQlSchemaState::new(
            sdl,
            schema,
            persisted_docs,
        )));
        self.record_success();
        Ok(true)
    }

    fn record_success(&self) {
        let sync = self.sync();
        sync.last_success_secs
            .store(now_unix_secs(), Ordering::Relaxed);
        sync.last_error.store(None);
    }
}

/// Seconds since the Unix epoch (0 on a pre-epoch clock).
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use apollo_compiler::validation::Valid;

    use super::*;
    use crate::GraphQlLayer;

    /// Answers [`INTROSPECTION_QUERY`] from `sdl` through apollo-compiler's
    /// own introspection execution — the fixtures are what a real GraphQL
    /// server returns, not hand-written JSON.
    fn introspect(sdl: &str) -> serde_json::Value {
        let schema = Schema::parse_and_validate(sdl, "schema.graphql").expect("valid test SDL");
        let doc =
            ExecutableDocument::parse_and_validate(&schema, INTROSPECTION_QUERY, "query.graphql")
                .expect("the introspection query is valid");
        let op = doc.operations.get(None).expect("one operation");
        let vars =
            apollo_compiler::request::coerce_variable_values(&schema, op, &Default::default())
                .expect("no variables to coerce");
        let resp = apollo_compiler::introspection::partial_execute(
            &schema,
            &schema.implementers_map(),
            &doc,
            op,
            &vars,
        )
        .expect("introspection executes");
        serde_json::to_value(&resp).expect("response serializes")
    }

    /// Converts and compiles, panicking with the reason on failure.
    fn round_trip(sdl: &str) -> (String, Valid<Schema>) {
        let converted = introspection_to_sdl(&introspect(sdl)).expect("conversion succeeds");
        let schema = Schema::parse_and_validate(&converted, "converted.graphql")
            .unwrap_or_else(|e| panic!("converted SDL does not compile:\n{converted}\n{e:?}"));
        (converted, schema)
    }

    #[test]
    fn kitchen_sink_schema_round_trips() {
        let (converted, schema) = round_trip(
            r#"
            "The root."
            type Query implements Node {
                id: ID!
                hello(name: String = "world", count: Int = 3, ids: [ID!] = ["a"]): String
                matrix: [[Int!]]!
                node(filter: Filter = { limit: 10 }): Node
                animal: Animal
                old: String @deprecated(reason: "use hello")
            }
            type Mutation { poke(input: Filter!): Boolean }
            type Subscription { ticks: Int }
            interface Node { id: ID! }
            interface Pet implements Node { id: ID! name: String }
            type Dog implements Pet & Node { id: ID! name: String barks: Boolean }
            type Cat implements Pet & Node { id: ID! name: String }
            union Animal = Dog | Cat
            """
            Statuses, with an embedded \""" in the description.
            """
            enum Status {
                ACTIVE
                RETIRED @deprecated(reason: "gone \"forever\"")
            }
            input Filter { limit: Int = 10 tag: String }
            scalar Money
            directive @auth(role: String = "user") on FIELD_DEFINITION | OBJECT
            "#,
        );

        for needle in [
            "type Query implements Node",
            "hello(name: String = \"world\", count: Int = 3, ids: [ID!] = [\"a\"])",
            "matrix: [[Int!]]!",
            "interface Pet implements Node",
            "type Dog implements Pet & Node",
            "union Animal = Dog | Cat",
            "@deprecated(reason: \"use hello\")",
            "@deprecated(reason: \"gone \\\"forever\\\"\")",
            "input Filter",
            "scalar Money",
            "directive @auth(role: String = \"user\") on FIELD_DEFINITION | OBJECT",
        ] {
            assert!(
                converted.contains(needle),
                "missing `{needle}` in:\n{converted}"
            );
        }
        // The embedded `"""` survived as an escape.
        assert!(
            converted.contains("\\\"\"\""),
            "escaped block quotes missing"
        );
        // Mutation and subscription roots are wired.
        assert!(schema.schema_definition.mutation.is_some());
        assert!(schema.schema_definition.subscription.is_some());
        // Converting the converted schema again is a fixed point (stable
        // SDL comparison is what drives change detection).
        let again = introspection_to_sdl(&introspect(&converted)).expect("second conversion");
        assert_eq!(converted, again);
    }

    #[test]
    fn non_standard_root_names_get_a_schema_block() {
        let (converted, schema) =
            round_trip("schema { query: MyQuery } type MyQuery { ping: String }");
        assert!(
            converted.contains("schema {"),
            "missing schema block:\n{converted}"
        );
        assert_eq!(
            schema
                .schema_definition
                .query
                .as_ref()
                .expect("root")
                .name
                .as_str(),
            "MyQuery"
        );
    }

    #[test]
    fn builtins_are_skipped() {
        let (converted, _) =
            round_trip("type Query { n: Int s: String b: Boolean id: ID f: Float }");
        for absent in [
            "scalar Int",
            "scalar String",
            "scalar Boolean",
            "scalar ID",
            "scalar Float",
            "directive @skip",
            "directive @include",
            "directive @deprecated",
            "directive @specifiedBy",
            "__Type",
        ] {
            assert!(
                !converted.contains(absent),
                "`{absent}` leaked into:\n{converted}"
            );
        }
    }

    #[test]
    fn envelope_variants_are_accepted() {
        let full = introspect("type Query { hello: String }");
        let bare = full.get("data").expect("data").clone();
        let a = introspection_to_sdl(&full).expect("full envelope");
        let b = introspection_to_sdl(&bare).expect("bare __schema object");
        assert_eq!(a, b);
    }

    #[test]
    fn unusable_responses_are_errors() {
        let err = introspection_to_sdl(&serde_json::json!({
            "errors": [{ "message": "introspection is not allowed" }]
        }))
        .expect_err("errors-only response");
        assert!(err.contains("introspection is not allowed"), "got: {err}");

        let err = introspection_to_sdl(&serde_json::json!({})).expect_err("empty");
        assert!(err.contains("__schema"), "got: {err}");

        let err = introspection_to_sdl(&serde_json::json!({ "__schema": { "types": 42 } }))
            .expect_err("malformed");
        assert!(err.contains("introspection shape"), "got: {err}");

        let err = introspection_to_sdl(&serde_json::json!({
            "__schema": { "queryType": null, "types": [] }
        }))
        .expect_err("no query root");
        assert!(err.contains("query root"), "got: {err}");
    }

    #[test]
    fn descriptions_ending_in_a_quote_still_compile() {
        round_trip(r#""He said \"hi\"" type Query { hello: String }"#);
    }

    // --- swap semantics -------------------------------------------------

    const SEED: &str = "type Query { hello: String }";
    const GROWN: &str = "type Query { hello: String extra: Int }";

    fn synced_layer(graphql: serde_json::Value) -> (GraphQlLayer, GraphQlSyncHandle) {
        let def: g2_core::ApiDefinition = serde_json::from_str(
            &serde_json::json!({
                "api_id": "gql",
                "name": "gql",
                "listen_path": "/gql/",
                "target_url": "http://gql.internal/graphql",
                "auth": { "mode": "keyless" },
                "graphql": graphql
            })
            .to_string(),
        )
        .expect("valid definition");
        def.validate().expect("valid definition");
        let layer = GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def, None, None)
            .expect("compiles")
            .expect("enabled");
        let handle = layer.sync_handle().expect("sync configured");
        (layer, handle)
    }

    fn base() -> serde_json::Value {
        serde_json::json!({ "schema": SEED, "schema_sync": {} })
    }

    /// Whether `query` validates against the layer's current schema.
    fn validates(handle: &GraphQlSyncHandle, query: &str) -> bool {
        let state = handle.shared.state.load();
        ExecutableDocument::parse_and_validate(&state.schema, query, "q.graphql").is_ok()
    }

    #[test]
    fn sync_handle_exists_only_when_configured() {
        let (layer, _) = synced_layer(base());
        assert!(layer.sync_handle().is_some());

        let def: g2_core::ApiDefinition = serde_json::from_str(
            &serde_json::json!({
                "api_id": "gql", "name": "gql", "listen_path": "/gql/",
                "target_url": "http://gql.internal/graphql",
                "auth": { "mode": "keyless" },
                "graphql": { "schema": SEED }
            })
            .to_string(),
        )
        .expect("valid definition");
        let plain = GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def, None, None)
            .expect("compiles")
            .expect("enabled");
        assert!(plain.sync_handle().is_none());
    }

    #[test]
    fn apply_swaps_and_unchanged_sdl_is_a_noop() {
        let (_, handle) = synced_layer(base());
        assert!(handle.status().last_success_unix_secs.is_none());
        assert!(!validates(&handle, "{ extra }"));

        let grown = introspect(GROWN);
        assert_eq!(handle.apply_introspection(&grown), Ok(true));
        assert!(validates(&handle, "{ extra }"));
        assert!(handle.status().last_success_unix_secs.is_some());

        // Same response again: recorded as success, state untouched.
        let before = handle.shared.state.load_full();
        assert_eq!(handle.apply_introspection(&grown), Ok(false));
        assert!(Arc::ptr_eq(&before, &handle.shared.state.load_full()));
    }

    #[test]
    fn failures_keep_the_old_schema_and_surface_in_status() {
        let (_, handle) = synced_layer(base());
        let before = handle.shared.state.load_full();

        let err = handle
            .apply_introspection(&serde_json::json!({}))
            .expect_err("no __schema");
        handle.record_error(err.clone());
        assert!(Arc::ptr_eq(&before, &handle.shared.state.load_full()));
        assert_eq!(handle.status().last_error, Some(err));
        assert!(validates(&handle, "{ hello }"));

        // The next success clears the error.
        assert_eq!(handle.apply_introspection(&introspect(GROWN)), Ok(true));
        assert!(handle.status().last_error.is_none());
    }

    #[test]
    fn persisted_revalidation_failure_fails_the_whole_sync() {
        let (_, handle) = synced_layer(serde_json::json!({
            "schema": SEED,
            "schema_sync": {},
            "persisted_queries": [{
                "method": "GET", "path": "/hello", "operation": "{ hello }"
            }]
        }));
        let before = handle.shared.state.load_full();

        // A schema without `hello` invalidates the persisted operation.
        let err = handle
            .apply_introspection(&introspect("type Query { renamed: String }"))
            .expect_err("persisted op invalid");
        assert!(err.contains("persisted query [0]"), "got: {err}");
        assert!(Arc::ptr_eq(&before, &handle.shared.state.load_full()));

        // A schema keeping `hello` swaps and re-validates the doc.
        assert_eq!(handle.apply_introspection(&introspect(GROWN)), Ok(true));
        assert_eq!(handle.shared.state.load().persisted_docs.len(), 1);
    }

    #[tokio::test]
    async fn trigger_wakes_the_waiter_and_permits_are_stored() {
        let (_, handle) = synced_layer(base());

        // A trigger before anyone waits is stored and consumed immediately.
        handle.trigger();
        tokio::time::timeout(
            Duration::from_secs(5),
            handle.nudge().wait_interval(Duration::from_secs(3600)),
        )
        .await
        .expect("stored permit wakes the first wait");

        // A trigger while waiting wakes the waiter — through a detached
        // nudge, which must not keep the layer state alive.
        let nudge = handle.nudge();
        let waiter = tokio::spawn(async move {
            nudge.wait_interval(Duration::from_secs(3600)).await;
        });
        tokio::task::yield_now().await;
        handle.trigger();
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("trigger wakes the waiter")
            .expect("waiter task");
    }

    #[tokio::test]
    async fn weak_handle_dies_with_the_layer() {
        let (layer, handle) = synced_layer(base());
        let weak = handle.downgrade();
        assert!(weak.upgrade().is_some());
        drop(layer);
        drop(handle);
        assert!(weak.upgrade().is_none());
    }
}
