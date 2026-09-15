//! Federation supergraph execution (milestone M9, ADR-0011): the gateway
//! answers GraphQL queries by fetching each root field from the subgraph
//! that owns it and resolving cross-subgraph entity fields via
//! `_entities` fetches.
//!
//! Execution extends the ADR-0010 three-phase engine with a *planning*
//! walk and iterative entity resolution:
//!
//! 1. **Record** — [`Recorder`](crate::graphql_udg::Recorder) notes each
//!    requested root field (ADR-0010 §1, reused verbatim).
//! 2. **Plan** — each root field's selection tree is split by ownership
//!    ([`Planner`]): fields the owning subgraph resolves print into its
//!    sub-query; a field on an entity type owned elsewhere becomes a
//!    [`FetchNode`] (one per target subgraph per selection set), and the
//!    parent's printed selection gains `__typename` plus the target's key
//!    fields (aliased `g2__<field>` so client aliases can never collide).
//!    Fragment spreads are inlined, so subgraphs never need the client's
//!    fragment definitions.
//! 3. **Fetch** — the owner is fetched (concurrently across query root
//!    fields, serially for mutations), then per level: representations are
//!    collected from the returned JSON along each node's recorded
//!    response-key path, one `_entities` query per node is `POST`ed,
//!    grandchildren resolve against the returned entity values, and each
//!    entity's fields merge back into its source object.
//! 4. **Stitch** — ADR-0010's second engine pass over the merged JSON,
//!    keyed by response key ([`PrefetchedRoot`](crate::graphql_udg)).
//!
//! Failure semantics follow ADR-0010 §7: a subgraph failure names only the
//! subgraph (detail logged); unmerged entity fields become nulls with
//! positioned errors via the stitch pass's nullability handling; upstream
//! GraphQL errors are appended message-only.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

use apollo_compiler::ast;
use apollo_compiler::collections::IndexMap;
use apollo_compiler::executable::{ExecutableDocument, Operation, OperationType, Selection};
use apollo_compiler::resolvers::{Execution, FieldError};
use apollo_compiler::response::{GraphQLError, JsonMap, JsonValue};
use apollo_compiler::validation::Valid;
use apollo_compiler::Name;
use bytes::Bytes;
use futures_util::future::{join_all, BoxFuture};
use g2_core::federation::ComposedSupergraph;
use g2_core::graphql::{SupergraphConfig, DEFAULT_UDG_MAX_RESPONSE_BYTES};
use g2_core::{ApiDefinition, Error};
use http::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use http::{Method, Response, StatusCode};

use crate::graphql::{graphql_errors, GraphQlSchemaState};
use crate::graphql_udg::{
    collect_directives, collect_value, execution_response, field_error, FetchOutcome, KeyBy,
    PrefetchedRoot, RecordedField, Recorder,
};
use crate::udg_fetch::{SharedUdgFetch, UdgRequest};
use crate::ProxyBody;

/// One API's compiled supergraph execution state: the per-subgraph
/// endpoints and the composition's ownership tables.
pub(crate) struct SupergraphEngine {
    api_id: String,
    subgraphs: Vec<CompiledSubgraph>,
    /// `"Type.field"` → subgraphs resolving it (root and entity fields).
    field_owners: HashMap<String, Vec<usize>>,
    /// Entity type → per-subgraph canonical key (ADR-0011 §4).
    entity_keys: HashMap<String, Vec<Option<Vec<String>>>>,
    fetch: SharedUdgFetch,
}

impl std::fmt::Debug for SupergraphEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupergraphEngine")
            .field("api_id", &self.api_id)
            .field("subgraphs", &self.subgraphs.len())
            .field("entities", &self.entity_keys.len())
            .finish_non_exhaustive()
    }
}

/// One subgraph, precompiled: endpoint, static headers, caps.
struct CompiledSubgraph {
    name: String,
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    timeout: Duration,
    max_response_bytes: usize,
}

impl SupergraphEngine {
    /// Compiles the supergraph execution state from the validated config
    /// and its composition.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a header does not
    /// compile — normally impossible after
    /// [`GraphQlConfig::validate`](g2_core::GraphQlConfig::validate), but
    /// route building must not panic on a definition that skipped it.
    pub(crate) fn compile(
        config: &SupergraphConfig,
        composed: &ComposedSupergraph,
        def: &ApiDefinition,
        fetch: SharedUdgFetch,
    ) -> Result<Self, Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: def.api_id.clone(),
            reason,
        };
        let mut subgraphs = Vec::with_capacity(config.subgraphs.len());
        for (index, sub) in config.subgraphs.iter().enumerate() {
            let mut headers = Vec::with_capacity(sub.headers.len());
            for (name, value) in &sub.headers {
                let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    fail(format!(
                        "`graphql.supergraph.subgraphs[{index}].headers` name is not a \
                         valid header name: `{name}`"
                    ))
                })?;
                let value = HeaderValue::from_str(value).map_err(|_| {
                    fail(format!(
                        "`graphql.supergraph.subgraphs[{index}].headers` value for \
                         `{name}` is not a valid header value"
                    ))
                })?;
                headers.push((header, value));
            }
            subgraphs.push(CompiledSubgraph {
                name: sub.name.clone(),
                url: sub.url.clone(),
                headers,
                timeout: Duration::from_millis(sub.timeout_ms.unwrap_or(def.upstream_timeout_ms)),
                max_response_bytes: usize::try_from(
                    sub.max_response_bytes
                        .unwrap_or(DEFAULT_UDG_MAX_RESPONSE_BYTES),
                )
                .unwrap_or(usize::MAX),
            });
        }
        Ok(Self {
            api_id: def.api_id.clone(),
            subgraphs,
            field_owners: composed
                .field_owners
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            entity_keys: composed
                .entity_keys
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            fetch,
        })
    }
}

/// Executes a validated document across the subgraphs and builds the HTTP
/// response: `400` for request-level failures, `200` with spec-shaped
/// `data`/`errors` otherwise.
pub(crate) async fn execute(
    engine: &SupergraphEngine,
    state: &GraphQlSchemaState,
    doc: &Valid<ExecutableDocument>,
    operation_name: Option<&str>,
    raw_variables: JsonMap,
) -> Response<ProxyBody> {
    // The gateway is the executor: an ambiguous operationName must resolve
    // here (the ADR-0010 §7 rule).
    let op = match doc.operations.get(operation_name) {
        Ok(op) => op,
        Err(_) => {
            let message = match operation_name {
                Some(name) => format!("operation `{name}` is not defined in the document"),
                None => "the document defines multiple operations; \
                         set operationName to pick one"
                    .to_owned(),
            };
            return graphql_errors(StatusCode::BAD_REQUEST, [message]);
        }
    };
    let root_type = op.object_type().as_str();

    // Phase 1 — record (ADR-0010 §1).
    let recorder = Recorder {
        fields: RefCell::new(Vec::new()),
        root_type,
    };
    let recorded = {
        let collect = Execution::new(&state.schema, doc)
            .operation(op)
            .raw_variable_values(&raw_variables)
            .execute_sync(&recorder);
        match collect {
            Ok(_skipped) => recorder.fields.into_inner(),
            Err(request_error) => {
                return graphql_errors(
                    StatusCode::BAD_REQUEST,
                    [request_error.message().to_string()],
                );
            }
        }
    };

    // Phases 2+3 — plan and fetch each root field, resolving its entity
    // fetches to completion: concurrently for queries, serially (in
    // selection order) for mutations.
    let outcomes: Vec<FetchOutcome> = if op.operation_type == OperationType::Mutation {
        let mut outcomes = Vec::with_capacity(recorded.len());
        for field in &recorded {
            outcomes.push(run_root(engine, doc, op, field, &raw_variables).await);
        }
        outcomes
    } else {
        join_all(
            recorded
                .iter()
                .map(|field| run_root(engine, doc, op, field, &raw_variables)),
        )
        .await
    };
    let mut upstream_errors = Vec::new();
    let mut values = HashMap::with_capacity(outcomes.len());
    for mut outcome in outcomes {
        upstream_errors.append(&mut outcome.upstream_errors);
        values.insert(
            std::mem::take(&mut outcome.response_key),
            RefCell::new(Some(outcome)),
        );
    }

    // Phase 4 — stitch (ADR-0010 §1).
    let root = PrefetchedRoot { root_type, values };
    let result = Execution::new(&state.schema, doc)
        .operation(op)
        .raw_variable_values(&raw_variables)
        .enable_schema_introspection(true)
        .execute_sync(&root);
    match result {
        Err(request_error) => graphql_errors(
            StatusCode::BAD_REQUEST,
            [request_error.message().to_string()],
        ),
        Ok(mut response) => {
            response.errors.extend(upstream_errors);
            execution_response(&response)
        }
    }
}

/// One planned upstream fetch below a parent fetch: the `_entities` call
/// resolving foreign fields of one entity type from one subgraph.
struct FetchNode {
    /// Response-key path from the parent fetch's data root to the entity
    /// objects (arrays flatten; type conditions filter by `__typename`).
    path: Vec<PathSeg>,
    /// The entity type the representations name.
    type_name: String,
    subgraph: usize,
    key_fields: Vec<String>,
    /// The entity's pruned selection text (no outer braces).
    text: String,
    /// Variables the selection uses.
    vars: HashSet<Name>,
    children: Vec<FetchNode>,
}

/// One step of a [`FetchNode`] path.
enum PathSeg {
    /// Descend into this response key.
    Key(String),
    /// Keep only objects whose `__typename` matches (inline fragments).
    TypeCond(String),
}

/// The plan for one recorded root field.
struct RootPlan {
    subgraph: usize,
    /// The printed root field(s), pruned to the owner's slice.
    text: String,
    vars: HashSet<Name>,
    children: Vec<FetchNode>,
}

/// The ownership-splitting selection printer (ADR-0011 §5).
struct Planner<'a> {
    engine: &'a SupergraphEngine,
    doc: &'a Valid<ExecutableDocument>,
}

impl Planner<'_> {
    fn plan_root(&self, root_type: &str, field: &RecordedField) -> Result<RootPlan, String> {
        let owner_key = format!("{root_type}.{}", field.field_name);
        let owner = self
            .engine
            .field_owners
            .get(&owner_key)
            .and_then(|owners| owners.first().copied())
            .ok_or_else(|| format!("no subgraph resolves `{owner_key}`"))?;
        let mut text = String::new();
        let mut vars = HashSet::new();
        let mut children = Vec::new();
        for f in &field.selections {
            self.print_field(
                owner,
                f,
                &mut text,
                &mut vars,
                &mut children,
                &mut Vec::new(),
            )?;
            text.push('\n');
        }
        Ok(RootPlan {
            subgraph: owner,
            text,
            vars,
            children,
        })
    }

    /// Prints one field (alias, arguments, directives, pruned selections)
    /// for subgraph `sg`, extending `path` for cuts inside its selections.
    fn print_field(
        &self,
        sg: usize,
        f: &apollo_compiler::executable::Field,
        out: &mut String,
        vars: &mut HashSet<Name>,
        children: &mut Vec<FetchNode>,
        path: &mut Vec<PathSeg>,
    ) -> Result<(), String> {
        if let Some(alias) = &f.alias {
            out.push_str(alias);
            out.push_str(": ");
        }
        out.push_str(&f.name);
        if !f.arguments.is_empty() {
            out.push('(');
            for (i, arg) in f.arguments.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("{}: {}", arg.name, arg.value));
                collect_value(&arg.value, vars);
            }
            out.push(')');
        }
        print_directives(&f.directives, out, vars);
        if !f.selection_set.selections.is_empty() {
            out.push_str(" { ");
            path.push(PathSeg::Key(f.response_key().to_string()));
            self.print_set(
                sg,
                f.selection_set.ty.as_str(),
                &f.selection_set.selections,
                out,
                vars,
                children,
                path,
            )?;
            path.pop();
            out.push('}');
        }
        Ok(())
    }

    /// Prints a selection set's contents for subgraph `sg`, cutting foreign
    /// entity fields into [`FetchNode`]s. `__typename` is always included
    /// (representations and abstract-type stitching both need it).
    #[allow(clippy::too_many_arguments)] // internal recursion plumbing
    fn print_set(
        &self,
        sg: usize,
        parent_ty: &str,
        selections: &[Selection],
        out: &mut String,
        vars: &mut HashSet<Name>,
        children: &mut Vec<FetchNode>,
        path: &mut Vec<PathSeg>,
    ) -> Result<(), String> {
        out.push_str("__typename ");
        let entity = self.engine.entity_keys.contains_key(parent_ty);
        let mut foreign: IndexMap<usize, Vec<&apollo_compiler::executable::Field>> =
            IndexMap::default();
        for sel in selections {
            match sel {
                Selection::Field(f) => {
                    let local = f.name.starts_with("__")
                        || !entity
                        || match self
                            .engine
                            .field_owners
                            .get(&format!("{parent_ty}.{}", f.name))
                        {
                            Some(owners) => owners.contains(&sg),
                            // Defensive: an unmapped entity field stays
                            // local rather than failing the query.
                            None => true,
                        };
                    if local {
                        self.print_field(sg, f, out, vars, children, path)?;
                        out.push(' ');
                    } else {
                        let owners = &self.engine.field_owners[&format!("{parent_ty}.{}", f.name)];
                        let target = self.pick_target(parent_ty, owners)?;
                        foreign.entry(target).or_default().push(f);
                    }
                }
                Selection::InlineFragment(frag) => {
                    let cond = frag.selection_set.ty.as_str();
                    out.push_str("... on ");
                    out.push_str(cond);
                    print_directives(&frag.directives, out, vars);
                    out.push_str(" { ");
                    let conditioned = cond != parent_ty;
                    if conditioned {
                        path.push(PathSeg::TypeCond(cond.to_owned()));
                    }
                    self.print_set(
                        sg,
                        cond,
                        &frag.selection_set.selections,
                        out,
                        vars,
                        children,
                        path,
                    )?;
                    if conditioned {
                        path.pop();
                    }
                    out.push_str("} ");
                }
                Selection::FragmentSpread(spread) => {
                    // Inlined, so subgraphs never need the client's
                    // fragment definitions (ADR-0011 §5).
                    let Some(frag) = self.doc.fragments.get(&spread.fragment_name) else {
                        return Err(format!(
                            "fragment `{}` is not defined",
                            spread.fragment_name
                        ));
                    };
                    let cond = frag.selection_set.ty.as_str();
                    out.push_str("... on ");
                    out.push_str(cond);
                    print_directives(&spread.directives, out, vars);
                    out.push_str(" { ");
                    let conditioned = cond != parent_ty;
                    if conditioned {
                        path.push(PathSeg::TypeCond(cond.to_owned()));
                    }
                    self.print_set(
                        sg,
                        cond,
                        &frag.selection_set.selections,
                        out,
                        vars,
                        children,
                        path,
                    )?;
                    if conditioned {
                        path.pop();
                    }
                    out.push_str("} ");
                }
            }
        }
        // Cuts: inject the targets' key fields (aliased, collision-proof)
        // and build one child fetch per target subgraph.
        let mut injected: BTreeSet<&str> = BTreeSet::new();
        for (target, fields) in &foreign {
            let key = self.engine.entity_keys[parent_ty][*target]
                .as_ref()
                .expect("pick_target only picks subgraphs with a resolvable key");
            for k in key {
                if injected.insert(k) {
                    out.push_str(&format!("g2__{k}: {k} "));
                }
            }
            let mut ctext = String::new();
            let mut cvars = HashSet::new();
            let mut cchildren = Vec::new();
            for f in fields {
                self.print_field(
                    *target,
                    f,
                    &mut ctext,
                    &mut cvars,
                    &mut cchildren,
                    &mut Vec::new(),
                )?;
                ctext.push(' ');
            }
            children.push(FetchNode {
                path: path
                    .iter()
                    .map(|seg| match seg {
                        PathSeg::Key(k) => PathSeg::Key(k.clone()),
                        PathSeg::TypeCond(t) => PathSeg::TypeCond(t.clone()),
                    })
                    .collect(),
                type_name: parent_ty.to_owned(),
                subgraph: *target,
                key_fields: key.clone(),
                text: ctext,
                vars: cvars,
                children: cchildren,
            });
        }
        Ok(())
    }

    /// The first owner reachable via `_entities` (it has a resolvable key).
    fn pick_target(&self, ty: &str, owners: &[usize]) -> Result<usize, String> {
        owners
            .iter()
            .copied()
            .find(|s| {
                self.engine
                    .entity_keys
                    .get(ty)
                    .and_then(|keys| keys[*s].as_ref())
                    .is_some()
            })
            .ok_or_else(|| format!("no subgraph with a resolvable key can supply fields of `{ty}`"))
    }
}

/// Prints executable directives (`@skip`/`@include`/custom) and collects
/// the variables their arguments use.
fn print_directives(directives: &ast::DirectiveList, out: &mut String, vars: &mut HashSet<Name>) {
    for d in directives.iter() {
        out.push(' ');
        out.push_str(&d.to_string());
    }
    collect_directives(directives, vars);
}

/// The wire shape of a subgraph's GraphQL response.
#[derive(serde::Deserialize)]
struct SubResponse {
    #[serde(default)]
    data: Option<JsonMap>,
    #[serde(default)]
    errors: Vec<JsonValue>,
}

/// Builds the client-visible field error and logs the redacted detail
/// (ADR-0011 §6: clients see the subgraph name, the log sees everything).
fn subgraph_error(engine: &SupergraphEngine, name: &str, what: &str, detail: &str) -> FieldError {
    tracing::warn!(
        api_id = %engine.api_id,
        subgraph = %name,
        detail = %detail,
        "supergraph subgraph failure: {what}"
    );
    field_error(format!("subgraph `{name}` {what}"))
}

/// `POST`s one GraphQL request to a subgraph and parses the envelope.
async fn post_graphql(
    engine: &SupergraphEngine,
    subgraph: usize,
    query: String,
    variables: JsonMap,
) -> Result<SubResponse, FieldError> {
    let sub = &engine.subgraphs[subgraph];
    #[derive(serde::Serialize)]
    struct Request<'q> {
        query: &'q str,
        variables: &'q JsonMap,
    }
    let body = serde_json::to_vec(&Request {
        query: &query,
        variables: &variables,
    })
    .map_err(|e| {
        subgraph_error(
            engine,
            &sub.name,
            "failed to build the upstream query",
            &e.to_string(),
        )
    })?;
    let mut headers = sub.headers.clone();
    headers.push((CONTENT_TYPE, HeaderValue::from_static("application/json")));
    let response = engine
        .fetch
        .fetch(UdgRequest {
            method: Method::POST,
            url: sub.url.clone(),
            headers,
            body: Some(Bytes::from(body)),
            timeout: sub.timeout,
            max_response_bytes: sub.max_response_bytes,
        })
        .await
        .map_err(|e| subgraph_error(engine, &sub.name, "could not be reached", &e))?;
    if !response.status.is_success() {
        return Err(subgraph_error(
            engine,
            &sub.name,
            "answered a non-success status",
            response.status.as_str(),
        ));
    }
    serde_json::from_slice(&response.body)
        .map_err(|e| subgraph_error(engine, &sub.name, "returned invalid JSON", &e.to_string()))
}

/// Collects a subgraph's own `errors` as message-only response errors.
fn upstream_errors(name: &str, errors: &[JsonValue], out: &mut Vec<GraphQLError>) {
    for error in errors {
        let message = error
            .as_object()
            .and_then(|m| m.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("(no message)");
        out.push(GraphQLError {
            message: format!("subgraph `{name}`: {message}"),
            locations: Vec::new(),
            path: Vec::new(),
            extensions: JsonMap::new(),
        });
    }
}

/// A message-only response error (fetch-level failures below the root,
/// where the stitch pass already attributes the resulting null).
fn plain_error(message: String) -> GraphQLError {
    GraphQLError {
        message,
        locations: Vec::new(),
        path: Vec::new(),
        extensions: JsonMap::new(),
    }
}

/// Prints an operation wrapper: keyword, the variable definitions in
/// `vars` (plus `extra_def`, used for `$…representations`), and the body.
fn print_operation(
    keyword: &str,
    extra_def: Option<&str>,
    op: &Operation,
    vars: &HashSet<Name>,
    body: &str,
) -> String {
    let mut defs: Vec<String> = Vec::new();
    if let Some(extra) = extra_def {
        defs.push(extra.to_owned());
    }
    defs.extend(
        op.variables
            .iter()
            .filter(|v| vars.contains(&v.name))
            .map(|v| v.to_string()),
    );
    let mut out = keyword.to_owned();
    if !defs.is_empty() {
        out.push_str(&format!(" ({})", defs.join(", ")));
    }
    out.push_str(" {\n");
    out.push_str(body);
    out.push_str("\n}");
    out
}

/// The client's raw variables filtered to the used subset.
fn filtered_variables(raw: &JsonMap, vars: &HashSet<Name>) -> JsonMap {
    raw.iter()
        .filter(|(k, _)| vars.iter().any(|name| name.as_str() == k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// A representations-variable name that cannot shadow a client variable.
fn reps_var_name(op: &Operation) -> String {
    let mut name = "g2_representations".to_owned();
    while op.variables.iter().any(|v| v.name.as_str() == name) {
        name.push('_');
    }
    name
}

/// Plans and fully resolves one recorded root field.
async fn run_root(
    engine: &SupergraphEngine,
    doc: &Valid<ExecutableDocument>,
    op: &Operation,
    field: &RecordedField,
    raw_variables: &JsonMap,
) -> FetchOutcome {
    let mut outcome = FetchOutcome {
        response_key: field.response_key.clone(),
        value: Ok(JsonValue::Null),
        key_by: KeyBy::ResponseKey,
        source_key: String::new(),
        upstream_errors: Vec::new(),
    };
    let planner = Planner { engine, doc };
    let plan = match planner.plan_root(op.object_type().as_str(), field) {
        Ok(plan) => plan,
        Err(message) => {
            outcome.value = Err(field_error(message));
            return outcome;
        }
    };
    let sub_name = engine.subgraphs[plan.subgraph].name.clone();
    outcome.source_key = sub_name.clone();

    let keyword = match op.operation_type {
        OperationType::Query => "query",
        OperationType::Mutation => "mutation",
        OperationType::Subscription => "subscription",
    };
    let query = print_operation(keyword, None, op, &plan.vars, &plan.text);
    let variables = filtered_variables(raw_variables, &plan.vars);
    let parsed = match post_graphql(engine, plan.subgraph, query, variables).await {
        Ok(parsed) => parsed,
        Err(e) => {
            outcome.value = Err(e);
            return outcome;
        }
    };
    upstream_errors(&sub_name, &parsed.errors, &mut outcome.upstream_errors);
    let had_errors = !parsed.errors.is_empty();

    // Entity resolution walks the whole `data` object (the root field's
    // response key is the first path segment), then the field's value is
    // extracted for the stitch pass.
    let mut data = JsonValue::Object(parsed.data.unwrap_or_default());
    let nested = resolve_children(
        engine,
        std::slice::from_mut(&mut data),
        &plan.children,
        op,
        raw_variables,
    )
    .await;
    outcome.upstream_errors.extend(nested);

    let value = match data {
        JsonValue::Object(mut map) => map.remove(field.response_key.as_str()),
        _ => None,
    };
    outcome.value = match value {
        Some(value) => Ok(value),
        // The subgraph's own errors (already collected) explain the hole;
        // this error attributes the null to the right response path.
        None if had_errors => Err(field_error(format!(
            "subgraph `{sub_name}` returned errors"
        ))),
        None => Ok(JsonValue::Null),
    };
    outcome
}

/// Resolves one level of entity fetches against `values` (and, recursively,
/// every deeper level), merging fetched entity fields in place. Returns
/// the message-only errors gathered along the way.
fn resolve_children<'a>(
    engine: &'a SupergraphEngine,
    values: &'a mut [JsonValue],
    children: &'a [FetchNode],
    op: &'a Operation,
    raw_variables: &'a JsonMap,
) -> BoxFuture<'a, Vec<GraphQLError>> {
    Box::pin(async move {
        let mut errors = Vec::new();
        if children.is_empty() {
            return errors;
        }

        // Collect representations per child (immutably, so sibling fetches
        // can overlap even when their paths do).
        struct Prep {
            reps: Vec<JsonValue>,
            /// Which walked objects produced a representation, aligning the
            /// merge walk with the compacted reps list.
            mask: Vec<bool>,
        }
        let preps: Vec<Prep> = children
            .iter()
            .map(|child| {
                let mut maps = Vec::new();
                for value in values.iter() {
                    collect_maps(value, &child.path, &mut maps);
                }
                let mut reps = Vec::new();
                let mut mask = Vec::with_capacity(maps.len());
                for map in maps {
                    match representation(map, child) {
                        Some(rep) => {
                            reps.push(rep);
                            mask.push(true);
                        }
                        None => mask.push(false),
                    }
                }
                Prep { reps, mask }
            })
            .collect();

        // Fetch every child concurrently; grandchildren resolve against the
        // owned entity values before anything merges.
        let fetched: Vec<(Vec<JsonValue>, Vec<GraphQLError>)> =
            join_all(children.iter().zip(&preps).map(|(child, prep)| async move {
                if prep.reps.is_empty() {
                    return (Vec::new(), Vec::new());
                }
                let reps_var = reps_var_name(op);
                let body = format!(
                    "_entities(representations: ${reps_var}) {{ ... on {} {{ {} }} }}",
                    child.type_name, child.text
                );
                let query = print_operation(
                    "query",
                    Some(&format!("${reps_var}: [_Any!]!")),
                    op,
                    &child.vars,
                    &body,
                );
                let mut variables = filtered_variables(raw_variables, &child.vars);
                variables.insert(reps_var, JsonValue::Array(prep.reps.clone()));
                let sub_name = &engine.subgraphs[child.subgraph].name;
                match post_graphql(engine, child.subgraph, query, variables).await {
                    Err(e) => (Vec::new(), vec![plain_error(e.message)]),
                    Ok(parsed) => {
                        let mut errs = Vec::new();
                        upstream_errors(sub_name, &parsed.errors, &mut errs);
                        let mut entities: Vec<JsonValue> = parsed
                            .data
                            .and_then(|mut d| d.remove("_entities"))
                            .and_then(|v| match v {
                                JsonValue::Array(items) => Some(items),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let nested = resolve_children(
                            engine,
                            entities.as_mut_slice(),
                            &child.children,
                            op,
                            raw_variables,
                        )
                        .await;
                        errs.extend(nested);
                        (entities, errs)
                    }
                }
            }))
            .await;

        // Merge serially, re-walking each child's path (structure along
        // sibling paths is unchanged by earlier merges — merged fields are
        // new keys on entity objects).
        for ((child, prep), (entities, errs)) in children.iter().zip(&preps).zip(fetched) {
            errors.extend(errs);
            if prep.reps.is_empty() || entities.is_empty() {
                continue;
            }
            let mut maps = Vec::new();
            for value in values.iter_mut() {
                collect_maps_mut(value, &child.path, &mut maps);
            }
            if maps.len() != prep.mask.len() {
                // Unreachable by construction; degrade to nulls, loudly.
                tracing::warn!(
                    api_id = %engine.api_id,
                    "supergraph merge walk diverged from the collection walk"
                );
                errors.push(plain_error(format!(
                    "subgraph `{}` results could not be merged",
                    engine.subgraphs[child.subgraph].name
                )));
                continue;
            }
            let mut results = entities.into_iter();
            for (map, keep) in maps.into_iter().zip(&prep.mask) {
                if !keep {
                    continue;
                }
                let Some(entity) = results.next() else { break };
                // A null entity stays unmerged: the stitch pass nulls its
                // fields per nullability with positioned errors.
                if let JsonValue::Object(fields) = entity {
                    for (k, v) in fields {
                        map.insert(k, v);
                    }
                }
            }
        }
        errors
    })
}

/// Builds one `_Any` representation from a walked object: `__typename`
/// plus the key fields (read through the collision-proof `g2__` aliases the
/// planner injected). `None` skips the object — a stub the parent subgraph
/// chose not to identify resolves to nulls, not an error.
fn representation(map: &JsonMap, child: &FetchNode) -> Option<JsonValue> {
    if let Some(tn) = map.get("__typename").and_then(|v| v.as_str()) {
        if tn != child.type_name {
            return None;
        }
    }
    let mut rep = JsonMap::new();
    rep.insert("__typename", JsonValue::from(child.type_name.clone()));
    for key in &child.key_fields {
        let value = map
            .get(format!("g2__{key}").as_str())
            .or_else(|| map.get(key.as_str()))?;
        if value.is_null() {
            return None;
        }
        rep.insert(key.as_str(), value.clone());
    }
    Some(JsonValue::Object(rep))
}

/// Collects references to the objects a path names (arrays flatten, type
/// conditions filter, missing keys prune).
fn collect_maps<'v>(value: &'v JsonValue, path: &[PathSeg], out: &mut Vec<&'v JsonMap>) {
    match value {
        JsonValue::Array(items) => {
            for item in items {
                collect_maps(item, path, out);
            }
        }
        JsonValue::Object(map) => match path.first() {
            None => out.push(map),
            Some(PathSeg::Key(k)) => {
                if let Some(v) = map.get(k.as_str()) {
                    collect_maps(v, &path[1..], out);
                }
            }
            Some(PathSeg::TypeCond(t)) => {
                let matches = map.get("__typename").and_then(|v| v.as_str()) == Some(t.as_str());
                if matches {
                    collect_maps(value, &path[1..], out);
                }
            }
        },
        _ => {}
    }
}

/// [`collect_maps`], mutably (the merge walk).
fn collect_maps_mut<'v>(
    value: &'v mut JsonValue,
    path: &[PathSeg],
    out: &mut Vec<&'v mut JsonMap>,
) {
    if let JsonValue::Array(items) = value {
        for item in items {
            collect_maps_mut(item, path, out);
        }
        return;
    }
    if let Some(PathSeg::TypeCond(t)) = path.first() {
        let matches = value
            .as_object()
            .and_then(|m| m.get("__typename"))
            .and_then(|v| v.as_str())
            == Some(t.as_str());
        if matches {
            collect_maps_mut(value, &path[1..], out);
        }
        return;
    }
    if let JsonValue::Object(map) = value {
        match path.first() {
            None => out.push(map),
            Some(PathSeg::Key(k)) => {
                if let Some(v) = map.get_mut(k.as_str()) {
                    collect_maps_mut(v, &path[1..], out);
                }
            }
            Some(PathSeg::TypeCond(_)) => unreachable!("handled above"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use http_body_util::{BodyExt, Full};
    use tower::{Layer, ServiceExt};

    use super::*;
    use crate::graphql::GraphQlLayer;
    use crate::udg_fetch::{UdgFetch, UdgFetchFuture, UdgResponse};
    use http::Request;

    const USERS_SDL: &str = r#"
        type Query { user(id: ID!): User users: [User!]! }
        type User @key(fields: "id") { id: ID! name: String }
    "#;

    const REVIEWS_SDL: &str = r#"
        type Query { topReviews: [Review!]! }
        type Review { id: ID! body: String author: User }
        type User @key(fields: "id") {
            id: ID! @external
            reviews: [Review!]
        }
    "#;

    /// One captured subgraph call.
    #[derive(Debug, Clone)]
    struct Captured {
        url: String,
        body: String,
    }

    /// Routes on `(url, body substring)`, first match wins; records calls.
    #[derive(Default)]
    struct FakeFetch {
        calls: Mutex<Vec<Captured>>,
        routes: Vec<(String, String, u16, String)>,
    }

    impl FakeFetch {
        fn with(routes: &[(&str, &str, u16, &str)]) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                routes: routes
                    .iter()
                    .map(|(url, needle, status, body)| {
                        (
                            (*url).to_owned(),
                            (*needle).to_owned(),
                            *status,
                            (*body).to_owned(),
                        )
                    })
                    .collect(),
            })
        }

        fn calls(&self) -> Vec<Captured> {
            self.calls.lock().expect("not poisoned").clone()
        }
    }

    impl UdgFetch for FakeFetch {
        fn fetch(&self, request: UdgRequest) -> UdgFetchFuture {
            let body = request
                .body
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            let hit = self
                .routes
                .iter()
                .find(|(url, needle, _, _)| *url == request.url && body.contains(needle))
                .map(|(_, _, status, resp)| (*status, resp.clone()))
                .unwrap_or((404, "{}".to_owned()));
            self.calls.lock().expect("not poisoned").push(Captured {
                url: request.url,
                body,
            });
            Box::pin(async move {
                Ok(UdgResponse {
                    status: StatusCode::from_u16(hit.0).expect("test status"),
                    body: Bytes::from(hit.1),
                })
            })
        }
    }

    fn layer_for(subgraphs: serde_json::Value, fetch: Arc<FakeFetch>) -> GraphQlLayer {
        let def: ApiDefinition = serde_json::from_str(
            &serde_json::json!({
                "api_id": "fed",
                "name": "fed",
                "listen_path": "/fed/",
                "target_url": "http://unused.internal/",
                "auth": { "mode": "keyless" },
                "graphql": {
                    "execution_mode": "supergraph",
                    "supergraph": { "subgraphs": subgraphs }
                }
            })
            .to_string(),
        )
        .expect("valid definition");
        def.validate().expect("valid definition");
        GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def, Some(fetch), None)
            .expect("compiles")
            .expect("enabled")
    }

    fn users_reviews_layer(fetch: Arc<FakeFetch>) -> GraphQlLayer {
        layer_for(
            serde_json::json!([
                { "name": "users", "url": "http://users/graphql", "sdl": USERS_SDL },
                { "name": "reviews", "url": "http://reviews/graphql", "sdl": REVIEWS_SDL }
            ]),
            fetch,
        )
    }

    async fn no_forward(
        _req: Request<ProxyBody>,
    ) -> Result<Response<ProxyBody>, std::convert::Infallible> {
        panic!("supergraph mode must never call the inner service");
    }

    async fn send(layer: &GraphQlLayer, req: Request<ProxyBody>) -> Response<ProxyBody> {
        layer
            .clone()
            .layer(tower::service_fn(no_forward))
            .oneshot(req)
            .await
            .expect("infallible")
    }

    fn post(query: &str) -> Request<ProxyBody> {
        post_json(serde_json::json!({ "query": query }))
    }

    fn post_json(envelope: serde_json::Value) -> Request<ProxyBody> {
        Request::builder()
            .method(Method::POST)
            .uri("/fed")
            .body(ProxyBody::new(Full::new(Bytes::from(envelope.to_string()))))
            .expect("request")
    }

    async fn ok_json(layer: &GraphQlLayer, req: Request<ProxyBody>) -> serde_json::Value {
        let resp = send(layer, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn stitches_an_entity_field_across_subgraphs() {
        let fetch = FakeFetch::with(&[
            (
                "http://users/graphql",
                "user",
                200,
                r#"{"data":{"u":{"__typename":"User","name":"Ada","g2__id":"7"}}}"#,
            ),
            (
                "http://reviews/graphql",
                "_entities",
                200,
                r#"{"data":{"_entities":[
                    {"__typename":"User","reviews":[{"__typename":"Review","body":"good"}]}
                ]}}"#,
            ),
        ]);
        let layer = users_reviews_layer(Arc::clone(&fetch));
        let body = ok_json(
            &layer,
            post(r#"{ u: user(id: "7") { name reviews { body } } }"#),
        )
        .await;
        assert_eq!(
            body,
            serde_json::json!({
                "data": { "u": { "name": "Ada", "reviews": [{ "body": "good" }] } }
            })
        );

        let calls = fetch.calls();
        assert_eq!(calls.len(), 2);
        // The owner's query keeps the alias and gains __typename + the
        // aliased key; the foreign field never reaches it.
        assert_eq!(calls[0].url, "http://users/graphql");
        let root: serde_json::Value = serde_json::from_str(&calls[0].body).expect("json");
        let q = root["query"].as_str().expect("query");
        assert!(q.contains(r#"u: user(id: "7")"#), "got: {q}");
        assert!(q.contains("__typename"), "got: {q}");
        assert!(q.contains("g2__id: id"), "got: {q}");
        assert!(!q.contains("reviews"), "foreign field stays out: {q}");
        // The entity fetch carries the representation and the sub-selection.
        assert_eq!(calls[1].url, "http://reviews/graphql");
        let sub: serde_json::Value = serde_json::from_str(&calls[1].body).expect("json");
        let q = sub["query"].as_str().expect("query");
        assert!(
            q.contains("_entities(representations: $g2_representations)"),
            "got: {q}"
        );
        assert!(q.contains("... on User"), "got: {q}");
        assert!(q.contains("reviews"), "got: {q}");
        assert_eq!(
            sub["variables"]["g2_representations"],
            serde_json::json!([{ "__typename": "User", "id": "7" }])
        );
    }

    #[tokio::test]
    async fn entity_lists_batch_into_one_fetch_in_order() {
        let fetch = FakeFetch::with(&[
            (
                "http://users/graphql",
                "users",
                200,
                r#"{"data":{"users":[
                    {"__typename":"User","g2__id":"1"},
                    {"__typename":"User","g2__id":"2"}
                ]}}"#,
            ),
            (
                "http://reviews/graphql",
                "_entities",
                200,
                r#"{"data":{"_entities":[
                    {"__typename":"User","reviews":[{"__typename":"Review","body":"r1"}]},
                    {"__typename":"User","reviews":[]}
                ]}}"#,
            ),
        ]);
        let layer = users_reviews_layer(Arc::clone(&fetch));
        let body = ok_json(&layer, post("{ users { reviews { body } } }")).await;
        assert_eq!(
            body["data"]["users"],
            serde_json::json!([
                { "reviews": [{ "body": "r1" }] },
                { "reviews": [] }
            ])
        );
        let calls = fetch.calls();
        assert_eq!(calls.len(), 2, "one batched _entities call");
        let sub: serde_json::Value = serde_json::from_str(&calls[1].body).expect("json");
        assert_eq!(
            sub["variables"]["g2_representations"],
            serde_json::json!([
                { "__typename": "User", "id": "1" },
                { "__typename": "User", "id": "2" }
            ])
        );
    }

    #[tokio::test]
    async fn entity_below_a_value_type_is_resolved() {
        // Review is a reviews-only value type; its author is a User entity
        // whose `name` lives in the users subgraph.
        let fetch = FakeFetch::with(&[
            (
                "http://reviews/graphql",
                "topReviews",
                200,
                r#"{"data":{"topReviews":[
                    {"__typename":"Review","body":"b",
                     "author":{"__typename":"User","g2__id":"9"}}
                ]}}"#,
            ),
            (
                "http://users/graphql",
                "_entities",
                200,
                r#"{"data":{"_entities":[{"__typename":"User","name":"Zed"}]}}"#,
            ),
        ]);
        let layer = users_reviews_layer(Arc::clone(&fetch));
        let body = ok_json(&layer, post("{ topReviews { body author { name } } }")).await;
        assert_eq!(
            body["data"]["topReviews"],
            serde_json::json!([{ "body": "b", "author": { "name": "Zed" } }])
        );
    }

    #[tokio::test]
    async fn failed_entity_fetch_yields_nulls_and_names_only_the_subgraph() {
        let fetch = FakeFetch::with(&[(
            "http://users/graphql",
            "user",
            200,
            r#"{"data":{"user":{"__typename":"User","name":"Ada","g2__id":"7"}}}"#,
        )]);
        let layer = users_reviews_layer(fetch);
        let body = ok_json(
            &layer,
            post(r#"{ user(id: "7") { name reviews { body } } }"#),
        )
        .await;
        assert_eq!(body["data"]["user"]["name"], "Ada");
        assert_eq!(body["data"]["user"]["reviews"], serde_json::Value::Null);
        let messages: Vec<String> = body["errors"]
            .as_array()
            .expect("errors")
            .iter()
            .map(|e| e["message"].as_str().expect("message").to_owned())
            .collect();
        assert!(
            messages.iter().any(|m| m.contains("`reviews`")),
            "names the subgraph: {messages:?}"
        );
        assert!(
            messages.iter().all(|m| !m.contains("http://")),
            "no URLs leak: {messages:?}"
        );
    }

    #[tokio::test]
    async fn variables_and_directives_reach_the_right_fetches() {
        let fetch = FakeFetch::with(&[
            (
                "http://users/graphql",
                "user",
                200,
                r#"{"data":{"user":{"__typename":"User","g2__id":"7"}}}"#,
            ),
            (
                "http://reviews/graphql",
                "_entities",
                200,
                r#"{"data":{"_entities":[{"__typename":"User","reviews":[]}]}}"#,
            ),
        ]);
        let layer = users_reviews_layer(Arc::clone(&fetch));
        ok_json(
            &layer,
            post_json(serde_json::json!({
                "query": "query Q($id: ID!, $inc: Boolean!) \
                          { user(id: $id) { reviews @include(if: $inc) { body } } }",
                "variables": { "id": "7", "inc": true }
            })),
        )
        .await;
        let calls = fetch.calls();
        let root: serde_json::Value = serde_json::from_str(&calls[0].body).expect("json");
        assert!(
            root["query"].as_str().expect("q").contains("($id: ID!)"),
            "root gets only its variable: {root}"
        );
        assert_eq!(root["variables"], serde_json::json!({ "id": "7" }));
        let sub: serde_json::Value = serde_json::from_str(&calls[1].body).expect("json");
        let q = sub["query"].as_str().expect("q");
        assert!(q.contains("@include(if: $inc)"), "directive travels: {q}");
        assert!(q.contains("$inc: Boolean!"), "def travels: {q}");
        assert_eq!(sub["variables"]["inc"], serde_json::json!(true));
    }

    const CATALOG_SDL: &str = r#"
        type Query { node(id: ID!): Node }
        interface Node { id: ID! }
        type Book implements Node { id: ID! title: String }
        type User implements Node @key(fields: "id") { id: ID! name: String }
    "#;

    const KARMA_SDL: &str = r#"
        type Query { noop: Int }
        type User @key(fields: "id") { id: ID! @external karma: Int }
    "#;

    fn abstract_layer(fetch: Arc<FakeFetch>) -> GraphQlLayer {
        layer_for(
            serde_json::json!([
                { "name": "catalog", "url": "http://catalog/graphql", "sdl": CATALOG_SDL },
                { "name": "karma", "url": "http://karma/graphql", "sdl": KARMA_SDL }
            ]),
            fetch,
        )
    }

    #[tokio::test]
    async fn inline_fragment_cuts_filter_by_typename() {
        let query = r#"{ node(id: "1") { ... on User { karma } ... on Book { title } } }"#;

        // A Book: no representation collected, no entity fetch at all.
        let fetch = FakeFetch::with(&[(
            "http://catalog/graphql",
            "node",
            200,
            r#"{"data":{"node":{"__typename":"Book","title":"Dune","g2__id":"1"}}}"#,
        )]);
        let layer = abstract_layer(Arc::clone(&fetch));
        let body = ok_json(&layer, post(query)).await;
        assert_eq!(body["data"]["node"], serde_json::json!({ "title": "Dune" }));
        assert_eq!(fetch.calls().len(), 1, "no _entities call for a Book");

        // A User: the karma subgraph is consulted.
        let fetch = FakeFetch::with(&[
            (
                "http://catalog/graphql",
                "node",
                200,
                r#"{"data":{"node":{"__typename":"User","g2__id":"1"}}}"#,
            ),
            (
                "http://karma/graphql",
                "_entities",
                200,
                r#"{"data":{"_entities":[{"__typename":"User","karma":42}]}}"#,
            ),
        ]);
        let layer = abstract_layer(Arc::clone(&fetch));
        let body = ok_json(&layer, post(query)).await;
        assert_eq!(body["data"]["node"], serde_json::json!({ "karma": 42 }));
        assert_eq!(fetch.calls().len(), 2);
    }

    #[tokio::test]
    async fn two_hop_entity_chains_resolve() {
        let a = r#"type Query { top: Product }
                   type Product @key(fields: "sku") { sku: ID! }"#;
        let b = r#"type Query { noopB: Int }
                   type Product @key(fields: "sku") { sku: ID! @external seller: Seller }
                   type Seller @key(fields: "id") { id: ID! }"#;
        let c = r#"type Query { noopC: Int }
                   type Seller @key(fields: "id") { id: ID! @external rating: Int }"#;
        let fetch = FakeFetch::with(&[
            (
                "http://a/graphql",
                "top",
                200,
                r#"{"data":{"top":{"__typename":"Product","g2__sku":"s1"}}}"#,
            ),
            (
                "http://b/graphql",
                "_entities",
                200,
                r#"{"data":{"_entities":[
                    {"__typename":"Product",
                     "seller":{"__typename":"Seller","g2__id":"z"}}
                ]}}"#,
            ),
            (
                "http://c/graphql",
                "_entities",
                200,
                r#"{"data":{"_entities":[{"__typename":"Seller","rating":5}]}}"#,
            ),
        ]);
        let layer = layer_for(
            serde_json::json!([
                { "name": "a", "url": "http://a/graphql", "sdl": a },
                { "name": "b", "url": "http://b/graphql", "sdl": b },
                { "name": "c", "url": "http://c/graphql", "sdl": c }
            ]),
            Arc::clone(&fetch),
        );
        let body = ok_json(&layer, post("{ top { seller { rating } } }")).await;
        assert_eq!(
            body["data"],
            serde_json::json!({ "top": { "seller": { "rating": 5 } } })
        );
        assert_eq!(fetch.calls().len(), 3, "one hop per boundary");
    }

    #[tokio::test]
    async fn introspection_executes_locally_against_the_composed_schema() {
        let fetch = FakeFetch::with(&[]);
        let layer = users_reviews_layer(Arc::clone(&fetch));
        let body = ok_json(
            &layer,
            post(r#"{ __type(name: "User") { fields { name } } }"#),
        )
        .await;
        let fields: Vec<&str> = body["data"]["__type"]["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .map(|f| f["name"].as_str().expect("name"))
            .collect();
        assert!(fields.contains(&"name") && fields.contains(&"reviews"));
        assert!(fetch.calls().is_empty(), "no subgraph consulted");
    }

    #[tokio::test]
    async fn subgraph_own_errors_surface_prefixed() {
        let fetch = FakeFetch::with(&[(
            "http://users/graphql",
            "user",
            200,
            r#"{"data":{"user":null},"errors":[{"message":"not found"}]}"#,
        )]);
        let layer = users_reviews_layer(fetch);
        let body = ok_json(&layer, post(r#"{ user(id: "0") { name } }"#)).await;
        assert_eq!(body["data"]["user"], serde_json::Value::Null);
        assert!(
            body["errors"][0]["message"]
                .as_str()
                .expect("message")
                .contains("subgraph `users`: not found"),
            "got: {body}"
        );
    }

    #[tokio::test]
    async fn stub_without_key_resolves_foreign_fields_to_null_quietly() {
        // The parent subgraph answered without the key value: no
        // representation, no fetch, nulls per nullability.
        let fetch = FakeFetch::with(&[(
            "http://users/graphql",
            "user",
            200,
            r#"{"data":{"user":{"__typename":"User","name":"Ada","g2__id":null}}}"#,
        )]);
        let layer = users_reviews_layer(Arc::clone(&fetch));
        let body = ok_json(
            &layer,
            post(r#"{ user(id: "7") { name reviews { body } } }"#),
        )
        .await;
        assert_eq!(body["data"]["user"]["reviews"], serde_json::Value::Null);
        assert_eq!(fetch.calls().len(), 1, "no _entities call without a key");
    }
}
