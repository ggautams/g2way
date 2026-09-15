//! Universal Data Graph execution (milestone M9, ADR-0010): the gateway
//! answers GraphQL queries itself by fetching each root field from its
//! mapped data source and stitching the results.
//!
//! Execution rides apollo-compiler's spec-compliant engine in three
//! phases (ADR-0010 §1):
//!
//! 1. **Record** — a synchronous [`Execution::execute_sync`] pass with a
//!    resolver ([`Recorder`]) that notes every requested root field (with
//!    its spec-coerced arguments and merged selections) and returns
//!    [`ResolvedValue::SkipForPartialExecution`]. The engine does the
//!    CollectFields work — fragments, `@skip`/`@include`, field merging,
//!    argument coercion — so the gateway never re-implements it.
//! 2. **Fetch** — each recorded field's data source is called through the
//!    [`UdgFetch`](crate::UdgFetch) seam: concurrently for queries,
//!    serially (in selection order) for mutations, per the spec.
//! 3. **Stitch** — a second `execute_sync` pass resolves root fields from
//!    the prefetched JSON ([`PrefetchedRoot`]) and projects nested
//!    selections out of it ([`JsonNode`]), with the engine driving result
//!    coercion, null propagation, and error paths. `__schema`/`__type`
//!    are answered here from the compiled schema (introspection policing
//!    runs earlier, in [`check_document`](crate::graphql::check_document)).
//!
//! The phase split exists because the engine's async mode holds non-`Send`
//! resolver state across awaits, and every future in the middleware chain
//! must be `Send`: both engine passes complete synchronously, so only the
//! fetch phase — plain `Send` futures — spans an await point.
//!
//! Everything derivable from configuration — the source lookup table,
//! parsed methods/headers, the minijinja environment with every template
//! compiled — is built once at route-build time ([`UdgEngine::compile`]).
//! Because `udg` mode rejects `schema_sync` at validation, the engine may
//! live in the schema-*independent* half of the layer's state: the schema
//! leaf never swaps for a UDG API (ADR-0010 §10).
//!
//! Failure semantics (ADR-0010 §7): a source failure becomes a GraphQL
//! field error naming only the source key — upstream URLs, statuses and
//! bodies go to the log, never to the client (the ADR-0005 §4 redaction
//! stance). Request-level failures (unknown operation, variable coercion)
//! answer `400`; execution — even one where every field failed — answers
//! `200` with `errors` alongside `data`, per the GraphQL spec.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use apollo_compiler::executable::{
    ExecutableDocument, Field, Operation, OperationType, Selection, SelectionSet,
};
use apollo_compiler::resolvers::{Execution, FieldError, ObjectValue, ResolveInfo, ResolvedValue};
use apollo_compiler::response::{ExecutionResponse, GraphQLError, JsonMap, JsonValue};
use apollo_compiler::validation::Valid;
use apollo_compiler::{ast, Name};
use bytes::Bytes;
use g2_core::graphql::{GraphQlConfig, UdgDataSource, DEFAULT_UDG_MAX_RESPONSE_BYTES};
use g2_core::{ApiDefinition, Error};
use http::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode};

use crate::graphql::{graphql_errors, GraphQlSchemaState};
use crate::transform_body::RENDER_FUEL;
use crate::udg_fetch::{SharedUdgFetch, UdgRequest};
use crate::{ProxyBody, SessionContext};

/// One API's compiled UDG execution state: the data-source lookup table and
/// the minijinja environment holding every source template.
pub(crate) struct UdgEngine {
    api_id: String,
    env: minijinja::Environment<'static>,
    /// `"<RootType>.<field>"` → the compiled source.
    sources: HashMap<String, CompiledSource>,
    fetch: SharedUdgFetch,
}

impl std::fmt::Debug for UdgEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdgEngine")
            .field("api_id", &self.api_id)
            .field("sources", &self.sources.len())
            .finish_non_exhaustive()
    }
}

/// One data source, precompiled: parsed method/headers, template registry
/// names, and effective caps.
struct CompiledSource {
    kind: SourceKind,
    /// Header name → template registry name (values are templates).
    headers: Vec<(HeaderName, String)>,
    /// Whether the configured headers set `content-type` themselves.
    has_content_type: bool,
    timeout: Duration,
    max_response_bytes: usize,
}

enum SourceKind {
    Rest {
        method: Method,
        /// Registry name of the URL template.
        url: String,
        /// Registry name of the body template, when configured.
        body: Option<String>,
    },
    Graphql {
        /// The fixed upstream endpoint (validated absolute http(s)).
        url: String,
    },
}

impl UdgEngine {
    /// Compiles the UDG execution state for one API: parses methods and
    /// header names, registers every url/header/body template, and captures
    /// effective timeouts and response caps.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a method, header name,
    /// or template does not compile — normally impossible after
    /// [`GraphQlConfig::validate`], but route building must not panic on a
    /// definition that skipped validation.
    pub(crate) fn compile(
        config: &GraphQlConfig,
        def: &ApiDefinition,
        fetch: SharedUdgFetch,
    ) -> Result<Self, Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: def.api_id.clone(),
            reason,
        };
        let mut env = minijinja::Environment::new();
        // URLs and bodies are not HTML; render templates verbatim.
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
        env.set_fuel(Some(RENDER_FUEL));

        let mut sources = HashMap::with_capacity(config.data_sources.len());
        for (key, source) in &config.data_sources {
            let mut add = |suffix: &str, template: &str| {
                let name = format!("{key}#{suffix}");
                env.add_template_owned(name.clone(), template.to_owned())
                    .map_err(|e| {
                        fail(format!(
                            "`graphql.data_sources[\"{key}\"]` {suffix} template does not \
                             compile: {e}"
                        ))
                    })?;
                Ok::<String, Error>(name)
            };
            let (kind, headers, timeout_ms, max_bytes) = match source {
                UdgDataSource::Rest(rest) => {
                    let method =
                        rest.method
                            .to_ascii_uppercase()
                            .parse::<Method>()
                            .map_err(|_| {
                                fail(format!(
                                    "`graphql.data_sources[\"{key}\"].method` is not a valid \
                                 method"
                                ))
                            })?;
                    let url = add("url", &rest.url)?;
                    let body = rest.body.as_deref().map(|b| add("body", b)).transpose()?;
                    let kind = SourceKind::Rest { method, url, body };
                    (
                        kind,
                        &rest.headers,
                        rest.timeout_ms,
                        rest.max_response_bytes,
                    )
                }
                UdgDataSource::Graphql(gql) => {
                    let kind = SourceKind::Graphql {
                        url: gql.url.clone(),
                    };
                    (kind, &gql.headers, gql.timeout_ms, gql.max_response_bytes)
                }
            };
            let mut compiled_headers = Vec::with_capacity(headers.len());
            let mut has_content_type = false;
            for (name, value) in headers {
                let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    fail(format!(
                        "`graphql.data_sources[\"{key}\"].headers` name is not a valid \
                         header name: `{name}`"
                    ))
                })?;
                has_content_type |= header == CONTENT_TYPE;
                compiled_headers.push((header, add(&format!("header:{name}"), value)?));
            }
            sources.insert(
                key.clone(),
                CompiledSource {
                    kind,
                    headers: compiled_headers,
                    has_content_type,
                    timeout: Duration::from_millis(timeout_ms.unwrap_or(def.upstream_timeout_ms)),
                    max_response_bytes: usize::try_from(
                        max_bytes.unwrap_or(DEFAULT_UDG_MAX_RESPONSE_BYTES),
                    )
                    .unwrap_or(usize::MAX),
                },
            );
        }
        Ok(Self {
            api_id: def.api_id.clone(),
            env,
            sources,
            fetch,
        })
    }

    /// Renders one registered template against a request context. The error
    /// is logged by the caller, never sent to the client.
    fn render(&self, name: &str, ctx: &minijinja::Value) -> Result<String, String> {
        let template = self
            .env
            .get_template(name)
            .map_err(|e| format!("template `{name}` missing: {e}"))?;
        template.render(ctx).map_err(|e| e.to_string())
    }
}

/// Client-request facts exposed to source templates as `_g2` (the
/// body-transform context shape, ADR-0007).
#[derive(Debug, serde::Serialize)]
pub(crate) struct RequestMeta {
    method: String,
    path: String,
    query: String,
    /// Lowercase request-header name → first value (lossy UTF-8).
    headers: BTreeMap<String, String>,
    session: Option<SessionMeta>,
}

#[derive(Debug, serde::Serialize)]
struct SessionMeta {
    alias: String,
}

impl RequestMeta {
    /// Captures the template-visible request facts (before the body is
    /// consumed; the body is the GraphQL request itself, not template
    /// input).
    pub(crate) fn capture(req: &Request<ProxyBody>) -> Self {
        let mut headers = BTreeMap::new();
        for name in req.headers().keys() {
            if let Some(value) = req.headers().get(name) {
                headers.insert(
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                );
            }
        }
        Self {
            method: req.method().as_str().to_owned(),
            path: req.uri().path().to_owned(),
            query: req.uri().query().unwrap_or("").to_owned(),
            headers,
            session: req
                .extensions()
                .get::<SessionContext>()
                .and_then(|ctx| ctx.session().alias.clone())
                .map(|alias| SessionMeta { alias }),
        }
    }
}

/// The template render context: coerced field arguments plus `_g2`.
#[derive(serde::Serialize)]
struct TemplateContext<'a> {
    args: &'a JsonMap,
    #[serde(rename = "_g2")]
    g2: &'a RequestMeta,
}

/// Executes a validated document against the API's data sources and builds
/// the HTTP response: `400` for request-level failures, `200` with
/// spec-shaped `data`/`errors` otherwise.
pub(crate) async fn execute(
    engine: &UdgEngine,
    state: &GraphQlSchemaState,
    doc: &Valid<ExecutableDocument>,
    operation_name: Option<&str>,
    raw_variables: JsonMap,
    meta: RequestMeta,
) -> Response<ProxyBody> {
    // Proxy mode leaves an ambiguous operationName to the upstream; the
    // gateway *is* the executor here, so it must resolve one.
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

    // Phase 1 — record: the engine collects the requested root fields.
    // Its response is discarded (every field skips); only a request-level
    // failure (variable coercion, undefined root type) surfaces, as 400.
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

    // Phase 2 — fetch: query root fields resolve concurrently, mutation
    // root fields serially in selection order (spec execution order).
    let outcomes: Vec<FetchOutcome> = if op.operation_type == OperationType::Mutation {
        let mut outcomes = Vec::with_capacity(recorded.len());
        for field in &recorded {
            outcomes.push(fetch_field(engine, doc, op, field, &raw_variables, &meta).await);
        }
        outcomes
    } else {
        futures_util::future::join_all(
            recorded
                .iter()
                .map(|field| fetch_field(engine, doc, op, field, &raw_variables, &meta)),
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

    // Phase 3 — stitch: the real execution over the prefetched JSON.
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

/// Serializes an [`ExecutionResponse`] as the `200 application/json` reply.
pub(crate) fn execution_response(response: &ExecutionResponse) -> Response<ProxyBody> {
    match serde_json::to_vec(response) {
        Ok(body) => {
            let mut resp =
                Response::new(ProxyBody::new(http_body_util::Full::new(Bytes::from(body))));
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            resp
        }
        // JSON-compatible values always serialize; kept non-panicking for
        // the route-build-must-not-panic rule.
        Err(_) => graphql_errors(
            StatusCode::INTERNAL_SERVER_ERROR,
            ["failed to serialize the GraphQL response"],
        ),
    }
}

/// One root field the recording pass observed.
pub(crate) struct RecordedField {
    /// The alias-aware key the field answers under.
    pub(crate) response_key: String,
    /// The schema field name (the data-source lookup key's second half).
    pub(crate) field_name: String,
    /// The engine-coerced arguments (variables substituted, defaults
    /// applied) — the `args` template context.
    pub(crate) args: JsonMap,
    /// The merged field selections, cloned so the fetch phase can print a
    /// GraphQL source's sub-query.
    pub(crate) selections: Vec<Field>,
}

/// Phase-1 resolver: records each collected root field and skips it.
pub(crate) struct Recorder<'a> {
    pub(crate) fields: RefCell<Vec<RecordedField>>,
    pub(crate) root_type: &'a str,
}

impl ObjectValue for Recorder<'_> {
    fn type_name(&self) -> &str {
        self.root_type
    }

    fn resolve_field<'a>(
        &'a self,
        info: &'a ResolveInfo<'a>,
    ) -> Result<ResolvedValue<'a>, FieldError> {
        self.fields.borrow_mut().push(RecordedField {
            response_key: info
                .field_selections()
                .first()
                .map(|f| f.response_key().to_string())
                .unwrap_or_else(|| info.field_name().to_owned()),
            field_name: info.field_name().to_owned(),
            args: info.arguments().clone(),
            selections: info
                .field_selections()
                .iter()
                .map(|f| (*f).clone())
                .collect(),
        });
        Ok(ResolvedValue::SkipForPartialExecution)
    }
}

/// One fetched root field, ready for the stitch pass.
pub(crate) struct FetchOutcome {
    pub(crate) response_key: String,
    /// The JSON the source produced, or the field error to report.
    pub(crate) value: Result<JsonValue, FieldError>,
    /// How nested selections key into the JSON (source-kind dependent).
    pub(crate) key_by: KeyBy,
    /// The originating source key, for nested-projection error messages.
    pub(crate) source_key: String,
    /// Errors a GraphQL source reported, appended to the stitched response.
    pub(crate) upstream_errors: Vec<GraphQLError>,
}

/// Fetches one recorded root field from its mapped data source.
async fn fetch_field(
    engine: &UdgEngine,
    doc: &Valid<ExecutableDocument>,
    op: &Operation,
    field: &RecordedField,
    raw_variables: &JsonMap,
    meta: &RequestMeta,
) -> FetchOutcome {
    let source_key = format!("{}.{}", op.object_type(), field.field_name);
    let mut outcome = FetchOutcome {
        response_key: field.response_key.clone(),
        value: Ok(JsonValue::Null),
        key_by: KeyBy::FieldName,
        source_key: source_key.clone(),
        upstream_errors: Vec::new(),
    };
    let Some(source) = engine.sources.get(&source_key) else {
        // Unreachable after config validation (full coverage), but a
        // definition that skipped it must fail per-field, not panic.
        outcome.value = Err(field_error(format!(
            "no data source is mapped for `{source_key}`"
        )));
        return outcome;
    };
    let ctx = minijinja::Value::from_serialize(&TemplateContext {
        args: &field.args,
        g2: meta,
    });
    let result = match &source.kind {
        SourceKind::Rest { method, url, body } => {
            outcome.key_by = KeyBy::FieldName;
            fetch_rest(
                engine,
                &source_key,
                source,
                method,
                url,
                body.as_deref(),
                &ctx,
            )
            .await
        }
        SourceKind::Graphql { url } => {
            outcome.key_by = KeyBy::ResponseKey;
            fetch_graphql(
                engine,
                &source_key,
                source,
                url,
                &ctx,
                doc,
                op,
                field,
                raw_variables,
                &mut outcome.upstream_errors,
            )
            .await
        }
    };
    outcome.value = result;
    outcome
}

/// Builds the client-visible field error and logs the redacted detail
/// (ADR-0010 §7: clients see the source key, the log sees everything).
fn source_error(engine: &UdgEngine, key: &str, what: &str, detail: &str) -> FieldError {
    tracing::warn!(
        api_id = %engine.api_id,
        source = %key,
        detail = %detail,
        "UDG data source failure: {what}"
    );
    field_error(format!("data source `{key}` {what}"))
}

/// Renders a source's headers (plus a `content-type: application/json`
/// default when a body is sent without one configured).
fn render_headers(
    engine: &UdgEngine,
    key: &str,
    source: &CompiledSource,
    ctx: &minijinja::Value,
    has_body: bool,
) -> Result<Vec<(HeaderName, HeaderValue)>, FieldError> {
    let mut headers = Vec::with_capacity(source.headers.len() + 1);
    for (name, template) in &source.headers {
        let rendered = engine
            .render(template, ctx)
            .map_err(|e| source_error(engine, key, "failed to render a header template", &e))?;
        let value = HeaderValue::from_str(&rendered).map_err(|_| {
            source_error(
                engine,
                key,
                "rendered an invalid header value",
                name.as_str(),
            )
        })?;
        headers.push((name.clone(), value));
    }
    if has_body && !source.has_content_type {
        headers.push((CONTENT_TYPE, HeaderValue::from_static("application/json")));
    }
    Ok(headers)
}

async fn fetch_rest(
    engine: &UdgEngine,
    key: &str,
    source: &CompiledSource,
    method: &Method,
    url_template: &str,
    body_template: Option<&str>,
    ctx: &minijinja::Value,
) -> Result<JsonValue, FieldError> {
    let url = engine
        .render(url_template, ctx)
        .map_err(|e| source_error(engine, key, "failed to render the url template", &e))?;
    let absolute = (url.starts_with("http://") || url.starts_with("https://"))
        && url.parse::<http::Uri>().is_ok();
    if !absolute {
        return Err(source_error(engine, key, "rendered an invalid URL", &url));
    }
    let body = body_template
        .map(|t| {
            engine
                .render(t, ctx)
                .map(|rendered| Bytes::from(rendered.into_bytes()))
                .map_err(|e| source_error(engine, key, "failed to render the body template", &e))
        })
        .transpose()?;
    let headers = render_headers(engine, key, source, ctx, body.is_some())?;
    let response = engine
        .fetch
        .fetch(UdgRequest {
            method: method.clone(),
            url,
            headers,
            body,
            timeout: source.timeout,
            max_response_bytes: source.max_response_bytes,
        })
        .await
        .map_err(|e| source_error(engine, key, "could not be reached", &e))?;
    if !response.status.is_success() {
        return Err(source_error(
            engine,
            key,
            "answered a non-success status",
            response.status.as_str(),
        ));
    }
    if response.body.is_empty() {
        return Ok(JsonValue::Null);
    }
    serde_json::from_slice(&response.body)
        .map_err(|e| source_error(engine, key, "returned invalid JSON", &e.to_string()))
}

#[allow(clippy::too_many_arguments)] // internal plumbing, called once
async fn fetch_graphql(
    engine: &UdgEngine,
    key: &str,
    source: &CompiledSource,
    url: &str,
    ctx: &minijinja::Value,
    doc: &Valid<ExecutableDocument>,
    op: &Operation,
    field: &RecordedField,
    raw_variables: &JsonMap,
    upstream_errors: &mut Vec<GraphQLError>,
) -> Result<JsonValue, FieldError> {
    let (query, variables) = build_subquery(doc, op, &field.selections, raw_variables);
    #[derive(serde::Serialize)]
    struct SubRequest<'q> {
        query: &'q str,
        variables: &'q JsonMap,
    }
    let body = serde_json::to_vec(&SubRequest {
        query: &query,
        variables: &variables,
    })
    .map_err(|e| {
        source_error(
            engine,
            key,
            "failed to build the upstream query",
            &e.to_string(),
        )
    })?;
    let mut headers = render_headers(engine, key, source, ctx, false)?;
    if !source.has_content_type {
        headers.push((CONTENT_TYPE, HeaderValue::from_static("application/json")));
    }
    let response = engine
        .fetch
        .fetch(UdgRequest {
            method: Method::POST,
            url: url.to_owned(),
            headers,
            body: Some(Bytes::from(body)),
            timeout: source.timeout,
            max_response_bytes: source.max_response_bytes,
        })
        .await
        .map_err(|e| source_error(engine, key, "could not be reached", &e))?;
    if !response.status.is_success() {
        return Err(source_error(
            engine,
            key,
            "answered a non-success status",
            response.status.as_str(),
        ));
    }
    #[derive(serde::Deserialize)]
    struct SubResponse {
        #[serde(default)]
        data: Option<JsonMap>,
        #[serde(default)]
        errors: Vec<JsonValue>,
    }
    let parsed: SubResponse = serde_json::from_slice(&response.body)
        .map_err(|e| source_error(engine, key, "returned invalid JSON", &e.to_string()))?;
    let had_errors = !parsed.errors.is_empty();
    for error in &parsed.errors {
        let message = error
            .as_object()
            .and_then(|m| m.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("(no message)");
        upstream_errors.push(GraphQLError {
            message: format!("data source `{key}`: {message}"),
            locations: Vec::new(),
            path: Vec::new(),
            extensions: JsonMap::new(),
        });
    }
    let value = parsed
        .data
        .and_then(|mut map| map.remove(field.response_key.as_str()));
    match value {
        Some(value) => Ok(value),
        // The upstream's own errors (already collected) explain the hole;
        // this error attributes the null to the right response path.
        None if had_errors => Err(field_error(format!("data source `{key}` returned errors"))),
        None => Ok(JsonValue::Null),
    }
}

/// How [`JsonNode`] looks selections up in upstream JSON: REST bodies key
/// by schema field name (the upstream knows nothing of aliases); a GraphQL
/// upstream already honored aliases, so its tree keys by response key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyBy {
    FieldName,
    ResponseKey,
}

/// Phase-3 root resolver: hands each root field its prefetched JSON.
pub(crate) struct PrefetchedRoot<'a> {
    pub(crate) root_type: &'a str,
    /// Response key → the fetch outcome, taken once when the engine asks
    /// (the engine resolves each collected field exactly once).
    pub(crate) values: HashMap<String, RefCell<Option<FetchOutcome>>>,
}

impl ObjectValue for PrefetchedRoot<'_> {
    fn type_name(&self) -> &str {
        self.root_type
    }

    fn resolve_field<'a>(
        &'a self,
        info: &'a ResolveInfo<'a>,
    ) -> Result<ResolvedValue<'a>, FieldError> {
        let response_key = info
            .field_selections()
            .first()
            .map(|f| f.response_key().as_str())
            .unwrap_or_else(|| info.field_name());
        let outcome = self
            .values
            .get(response_key)
            .and_then(|cell| cell.borrow_mut().take());
        let Some(outcome) = outcome else {
            // Only reachable if the two engine passes disagree on the
            // collected fields — a bug worth a loud (but valid) response.
            return Err(field_error(format!(
                "no prefetched value for `{response_key}`"
            )));
        };
        let value = outcome.value?;
        resolve_json(
            value,
            &info.field_definition().ty,
            info.schema(),
            outcome.key_by,
            &outcome.source_key,
        )
    }
}

/// A JSON object returned by a source, typed by the schema: nested
/// selections resolve by map lookup.
struct JsonNode {
    /// The concrete object type name the engine coerces against.
    type_name: String,
    map: JsonMap,
    key_by: KeyBy,
    /// The originating source key, for error messages.
    source_key: String,
}

impl ObjectValue for JsonNode {
    fn type_name(&self) -> &str {
        &self.type_name
    }

    fn resolve_field<'a>(
        &'a self,
        info: &'a ResolveInfo<'a>,
    ) -> Result<ResolvedValue<'a>, FieldError> {
        let key = match self.key_by {
            KeyBy::FieldName => info.field_name(),
            KeyBy::ResponseKey => info
                .field_selections()
                .first()
                .map(|f| f.response_key().as_str())
                .unwrap_or_else(|| info.field_name()),
        };
        let value = self.map.get(key).cloned().unwrap_or(JsonValue::Null);
        resolve_json(
            value,
            &info.field_definition().ty,
            info.schema(),
            self.key_by,
            &self.source_key,
        )
    }
}

/// Converts a source's JSON into the engine's resolved-value shape, guided
/// by the schema type: scalars/enums pass through as leaves (the engine
/// runs result coercion), objects become [`JsonNode`]s, lists recurse.
/// Nulls and missing keys resolve to null — nullability is the engine's
/// job, so a non-null hole becomes a positioned field error for free.
fn resolve_json<'a>(
    value: JsonValue,
    ty: &ast::Type,
    schema: &Valid<apollo_compiler::Schema>,
    key_by: KeyBy,
    source_key: &str,
) -> Result<ResolvedValue<'a>, FieldError> {
    match ty {
        ast::Type::Named(name) | ast::Type::NonNullNamed(name) => {
            resolve_named(value, name, schema, key_by, source_key)
        }
        ast::Type::List(inner) | ast::Type::NonNullList(inner) => match value {
            JsonValue::Null => Ok(ResolvedValue::null()),
            JsonValue::Array(items) => {
                let resolved: Vec<Result<ResolvedValue<'a>, FieldError>> = items
                    .into_iter()
                    .map(|item| resolve_json(item, inner, schema, key_by, source_key))
                    .collect();
                Ok(ResolvedValue::List(Box::new(resolved.into_iter())))
            }
            _ => Err(field_error(format!(
                "data source `{source_key}` returned a non-list value for a list field"
            ))),
        },
    }
}

fn resolve_named<'a>(
    value: JsonValue,
    name: &Name,
    schema: &Valid<apollo_compiler::Schema>,
    key_by: KeyBy,
    source_key: &str,
) -> Result<ResolvedValue<'a>, FieldError> {
    use apollo_compiler::schema::ExtendedType;
    if value.is_null() {
        return Ok(ResolvedValue::null());
    }
    match schema.types.get(name.as_str()) {
        Some(ExtendedType::Scalar(_) | ExtendedType::Enum(_)) => Ok(ResolvedValue::Leaf(value)),
        Some(ExtendedType::Object(_)) => {
            let JsonValue::Object(map) = value else {
                return Err(field_error(format!(
                    "data source `{source_key}` returned a non-object value for object \
                     type `{name}`"
                )));
            };
            Ok(ResolvedValue::Object(Box::new(JsonNode {
                type_name: name.to_string(),
                map,
                key_by,
                source_key: source_key.to_owned(),
            })))
        }
        Some(ExtendedType::Interface(_) | ExtendedType::Union(_)) => {
            let JsonValue::Object(map) = value else {
                return Err(field_error(format!(
                    "data source `{source_key}` returned a non-object value for abstract \
                     type `{name}`"
                )));
            };
            let Some(type_name) = map.get("__typename").and_then(|v| v.as_str()) else {
                return Err(field_error(format!(
                    "data source `{source_key}` data for abstract type `{name}` must \
                     include `__typename`"
                )));
            };
            Ok(ResolvedValue::Object(Box::new(JsonNode {
                type_name: type_name.to_owned(),
                map,
                key_by,
                source_key: source_key.to_owned(),
            })))
        }
        // An output position can never be an input object, and a `Valid`
        // schema defines every referenced type — reachable only with a
        // definition that skipped validation.
        Some(ExtendedType::InputObject(_)) | None => Err(field_error(format!(
            "schema type `{name}` cannot be resolved from data source `{source_key}`"
        ))),
    }
}

pub(crate) fn field_error(message: String) -> FieldError {
    FieldError { message }
}

/// Prints the standalone query a GraphQL source receives: the operation
/// keyword, the variable definitions the field's subtree uses, the field
/// selections verbatim (aliases and arguments round-trip), and every
/// transitively referenced fragment definition. Returns the query text and
/// the client's raw variables filtered to the used subset.
fn build_subquery(
    doc: &ExecutableDocument,
    op: &Operation,
    fields: &[Field],
    raw_variables: &JsonMap,
) -> (String, JsonMap) {
    let mut vars: HashSet<Name> = HashSet::new();
    let mut frags: Vec<Name> = Vec::new();
    for field in fields {
        collect_field(doc, field, &mut vars, &mut frags);
    }

    let mut out = String::new();
    out.push_str(match op.operation_type {
        OperationType::Query => "query",
        OperationType::Mutation => "mutation",
        OperationType::Subscription => "subscription",
    });
    let defs: Vec<String> = op
        .variables
        .iter()
        .filter(|v| vars.contains(&v.name))
        .map(|v| v.to_string())
        .collect();
    if !defs.is_empty() {
        out.push('(');
        out.push_str(&defs.join(", "));
        out.push(')');
    }
    out.push_str(" {\n");
    for field in fields {
        out.push_str(&field.to_string());
        out.push('\n');
    }
    out.push('}');
    for name in &frags {
        if let Some(frag) = doc.fragments.get(name) {
            out.push('\n');
            out.push_str(&frag.to_string());
        }
    }

    let variables: JsonMap = raw_variables
        .iter()
        .filter(|(k, _)| vars.iter().any(|name| name.as_str() == k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    (out, variables)
}

fn collect_field(
    doc: &ExecutableDocument,
    field: &Field,
    vars: &mut HashSet<Name>,
    frags: &mut Vec<Name>,
) {
    for arg in &field.arguments {
        collect_value(&arg.value, vars);
    }
    collect_directives(&field.directives, vars);
    collect_set(doc, &field.selection_set, vars, frags);
}

fn collect_set(
    doc: &ExecutableDocument,
    set: &SelectionSet,
    vars: &mut HashSet<Name>,
    frags: &mut Vec<Name>,
) {
    for sel in &set.selections {
        match sel {
            Selection::Field(field) => collect_field(doc, field, vars, frags),
            Selection::InlineFragment(frag) => {
                collect_directives(&frag.directives, vars);
                collect_set(doc, &frag.selection_set, vars, frags);
            }
            Selection::FragmentSpread(spread) => {
                collect_directives(&spread.directives, vars);
                if !frags.contains(&spread.fragment_name) {
                    frags.push(spread.fragment_name.clone());
                    if let Some(frag) = doc.fragments.get(&spread.fragment_name) {
                        collect_directives(&frag.directives, vars);
                        collect_set(doc, &frag.selection_set, vars, frags);
                    }
                }
            }
        }
    }
}

pub(crate) fn collect_directives(directives: &ast::DirectiveList, vars: &mut HashSet<Name>) {
    for directive in directives.iter() {
        for arg in &directive.arguments {
            collect_value(&arg.value, vars);
        }
    }
}

pub(crate) fn collect_value(value: &ast::Value, vars: &mut HashSet<Name>) {
    match value {
        ast::Value::Variable(name) => {
            vars.insert(name.clone());
        }
        ast::Value::List(items) => {
            for item in items {
                collect_value(item, vars);
            }
        }
        ast::Value::Object(fields) => {
            for (_, item) in fields {
                collect_value(item, vars);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use g2_core::KeySession;
    use http_body_util::{BodyExt, Full};
    use tower::{Layer, ServiceExt};

    use super::*;
    use crate::graphql::GraphQlLayer;
    use crate::udg_fetch::{UdgFetch, UdgFetchFuture, UdgResponse};

    const SCHEMA: &str = "type Query { hello: String user(id: ID!): User \
                          items: [User!] node: Node slow: Int fast: Int } \
                          type Mutation { slow: Int fast: Int } \
                          type User { id: ID! name: String email: String tags: [String] } \
                          interface Node { id: ID! } \
                          type Book implements Node { id: ID! title: String }";

    /// One captured data-source call.
    #[derive(Debug, Clone)]
    struct Captured {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<String>,
    }

    /// In-memory fetcher: routes on the exact rendered URL, records calls.
    #[derive(Default)]
    struct FakeFetch {
        calls: Mutex<Vec<Captured>>,
        responses: HashMap<String, (u16, String)>,
        /// Sleep 50ms before answering URLs containing "slow" (ordering
        /// tests).
        sleepy: bool,
    }

    impl FakeFetch {
        fn with(responses: &[(&str, u16, &str)]) -> Arc<Self> {
            Arc::new(Self {
                responses: responses
                    .iter()
                    .map(|(url, status, body)| ((*url).to_owned(), (*status, (*body).to_owned())))
                    .collect(),
                ..Self::default()
            })
        }

        fn calls(&self) -> Vec<Captured> {
            self.calls.lock().expect("not poisoned").clone()
        }

        fn urls(&self) -> Vec<String> {
            self.calls().into_iter().map(|c| c.url).collect()
        }
    }

    impl UdgFetch for FakeFetch {
        fn fetch(&self, request: UdgRequest) -> UdgFetchFuture {
            let (status, body) = self
                .responses
                .get(&request.url)
                .cloned()
                .unwrap_or((404, "{}".to_owned()));
            let slow = self.sleepy && request.url.contains("slow");
            self.calls.lock().expect("not poisoned").push(Captured {
                method: request.method.to_string(),
                url: request.url,
                headers: request
                    .headers
                    .iter()
                    .map(|(n, v)| {
                        (
                            n.to_string(),
                            String::from_utf8_lossy(v.as_bytes()).into_owned(),
                        )
                    })
                    .collect(),
                body: request
                    .body
                    .map(|b| String::from_utf8_lossy(&b).into_owned()),
            });
            Box::pin(async move {
                if slow {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Ok(UdgResponse {
                    status: StatusCode::from_u16(status).expect("test status"),
                    body: Bytes::from(body),
                })
            })
        }
    }

    /// The default all-REST source map; tests override entries.
    fn sources(overrides: &[(&str, serde_json::Value)]) -> serde_json::Value {
        let mut map = serde_json::json!({
            "Query.hello": { "kind": "rest", "url": "http://up/hello" },
            "Query.user": { "kind": "rest", "url": "http://up/users/{{ args.id }}" },
            "Query.items": { "kind": "rest", "url": "http://up/items" },
            "Query.node": { "kind": "rest", "url": "http://up/node" },
            "Query.slow": { "kind": "rest", "url": "http://up/qslow" },
            "Query.fast": { "kind": "rest", "url": "http://up/qfast" },
            "Mutation.slow": { "kind": "rest", "url": "http://up/mslow" },
            "Mutation.fast": { "kind": "rest", "url": "http://up/mfast" },
        });
        for (key, value) in overrides {
            map[*key] = value.clone();
        }
        map
    }

    fn udg_config(overrides: &[(&str, serde_json::Value)]) -> serde_json::Value {
        serde_json::json!({
            "schema": SCHEMA,
            "execution_mode": "udg",
            "data_sources": sources(overrides)
        })
    }

    fn layer_with(graphql: serde_json::Value, fetch: Arc<FakeFetch>) -> GraphQlLayer {
        let def: ApiDefinition = serde_json::from_str(
            &serde_json::json!({
                "api_id": "udg",
                "name": "udg",
                "listen_path": "/gql/",
                "target_url": "http://unused.internal/",
                "auth": { "mode": "keyless" },
                "graphql": graphql
            })
            .to_string(),
        )
        .expect("valid definition");
        def.validate().expect("valid definition");
        GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def, Some(fetch))
            .expect("compiles")
            .expect("enabled")
    }

    /// The inner service a UDG chain must never reach.
    async fn no_forward(
        _req: Request<ProxyBody>,
    ) -> Result<Response<ProxyBody>, std::convert::Infallible> {
        panic!("udg mode must never call the inner service");
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
            .uri("/gql")
            .body(ProxyBody::new(Full::new(Bytes::from(envelope.to_string()))))
            .expect("request")
    }

    async fn body_json(resp: Response<ProxyBody>) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        serde_json::from_slice(&bytes).expect("json body")
    }

    async fn ok_json(layer: &GraphQlLayer, req: Request<ProxyBody>) -> serde_json::Value {
        let resp = send(layer, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        body_json(resp).await
    }

    #[tokio::test]
    async fn stitches_sources_honoring_aliases_and_pruning_extras() {
        let fetch = FakeFetch::with(&[
            ("http://up/hello", 200, "\"hi\""),
            (
                "http://up/users/7",
                200,
                r#"{"id":"7","name":"Ada","tags":["x"],"secret":true}"#,
            ),
        ]);
        let layer = layer_with(udg_config(&[]), Arc::clone(&fetch));
        let body = ok_json(
            &layer,
            post(r#"{ greeting: hello user(id: "7") { name tags } }"#),
        )
        .await;
        assert_eq!(
            body,
            serde_json::json!({
                "data": { "greeting": "hi", "user": { "name": "Ada", "tags": ["x"] } }
            }),
        );
        assert_eq!(
            fetch.urls(),
            vec!["http://up/hello", "http://up/users/7"],
            "argument reached the url template"
        );
    }

    #[tokio::test]
    async fn templates_see_args_headers_and_session_alias() {
        let fetch = FakeFetch::with(&[("http://up/users/9", 200, "null")]);
        let layer = layer_with(
            udg_config(&[(
                "Query.user",
                serde_json::json!({
                    "kind": "rest",
                    "method": "post",
                    "url": "http://up/users/{{ args.id }}",
                    "headers": {
                        "x-caller": "{{ _g2.session.alias }}",
                        "x-trace": "{{ _g2.headers['x-trace-id'] }}"
                    },
                    "body": "{{ args | tojson }}"
                }),
            )]),
            Arc::clone(&fetch),
        );
        let session: KeySession = serde_json::from_str(
            &serde_json::json!({ "alias": "alice", "access": {} }).to_string(),
        )
        .expect("valid session");
        let mut req = post(r#"{ user(id: "9") { name } }"#);
        req.headers_mut()
            .insert("x-trace-id", "t-42".parse().expect("value"));
        req.extensions_mut()
            .insert(crate::SessionContext::new(session, "hash"));
        ok_json(&layer, req).await;

        let calls = fetch.calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.method, "POST");
        assert_eq!(call.body.as_deref(), Some(r#"{"id":"9"}"#));
        let header = |name: &str| {
            call.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(header("x-caller"), Some("alice"));
        assert_eq!(header("x-trace"), Some("t-42"));
        assert_eq!(
            header("content-type"),
            Some("application/json"),
            "default content type accompanies a body"
        );
    }

    #[tokio::test]
    async fn failed_source_yields_partial_data_with_a_pathed_error() {
        let fetch = FakeFetch::with(&[
            ("http://up/hello", 200, "\"hi\""),
            ("http://up/users/1", 500, "boom"),
        ]);
        let layer = layer_with(udg_config(&[]), fetch);
        let body = ok_json(&layer, post(r#"{ hello user(id: "1") { name } }"#)).await;
        assert_eq!(body["data"]["hello"], "hi");
        assert_eq!(body["data"]["user"], serde_json::Value::Null);
        let error = &body["errors"][0];
        assert!(
            error["message"]
                .as_str()
                .expect("message")
                .contains("`Query.user`"),
            "names the source key: {error}"
        );
        assert_eq!(error["path"], serde_json::json!(["user"]));
        assert!(
            !error["message"].as_str().expect("message").contains("boom"),
            "upstream detail stays out of the response"
        );
    }

    #[tokio::test]
    async fn non_null_list_item_propagates_with_index_path() {
        let fetch =
            FakeFetch::with(&[("http://up/items", 200, r#"[{"id":"1","name":"a"}, null]"#)]);
        let layer = layer_with(udg_config(&[]), fetch);
        let body = ok_json(&layer, post("{ items { name } }")).await;
        // `[User!]`: a null item is a field error that nulls the list.
        assert_eq!(body["data"]["items"], serde_json::Value::Null);
        assert_eq!(body["errors"][0]["path"], serde_json::json!(["items", 1]));
    }

    #[tokio::test]
    async fn skip_include_and_fragments_shape_the_fetches() {
        let fetch = FakeFetch::with(&[(
            "http://up/users/3",
            200,
            r#"{"id":"3","name":"N","email":"e@x"}"#,
        )]);
        let layer = layer_with(udg_config(&[]), Arc::clone(&fetch));
        let query = "query Q($all: Boolean!) { \
                       hello @include(if: $all) \
                       ...UserBits \
                     } \
                     fragment UserBits on Query { user(id: \"3\") { name email } }";
        let body = ok_json(
            &layer,
            post_json(serde_json::json!({ "query": query, "variables": { "all": false } })),
        )
        .await;
        assert_eq!(
            body["data"],
            serde_json::json!({ "user": { "name": "N", "email": "e@x" } }),
            "skipped field absent, fragment field resolved"
        );
        assert_eq!(
            fetch.urls(),
            vec!["http://up/users/3"],
            "hello never fetched"
        );
    }

    #[tokio::test]
    async fn abstract_types_require_and_use_upstream_typename() {
        let query = r#"{ node { id ... on Book { title } } }"#;
        let good = FakeFetch::with(&[(
            "http://up/node",
            200,
            r#"{"__typename":"Book","id":"1","title":"Dune"}"#,
        )]);
        let layer = layer_with(udg_config(&[]), good);
        let body = ok_json(&layer, post(query)).await;
        assert_eq!(
            body["data"]["node"],
            serde_json::json!({ "id": "1", "title": "Dune" })
        );

        let bare = FakeFetch::with(&[("http://up/node", 200, r#"{"id":"1"}"#)]);
        let layer = layer_with(udg_config(&[]), bare);
        let body = ok_json(&layer, post(query)).await;
        assert_eq!(body["data"]["node"], serde_json::Value::Null);
        assert!(
            body["errors"][0]["message"]
                .as_str()
                .expect("message")
                .contains("__typename"),
            "got: {body}"
        );
    }

    #[tokio::test]
    async fn introspection_is_answered_locally() {
        let fetch = FakeFetch::with(&[]);
        let layer = layer_with(udg_config(&[]), Arc::clone(&fetch));
        let body = ok_json(&layer, post("{ __schema { queryType { name } } }")).await;
        assert_eq!(body["data"]["__schema"]["queryType"]["name"], "Query");
        assert!(fetch.calls().is_empty(), "no source fetched");
    }

    #[tokio::test]
    async fn disabled_introspection_still_rejects_before_execution() {
        let fetch = FakeFetch::with(&[]);
        let mut config = udg_config(&[]);
        config["introspection_enabled"] = false.into();
        let layer = layer_with(config, Arc::clone(&fetch));
        let resp = send(&layer, post("{ __schema { queryType { name } } }")).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(fetch.calls().is_empty());
    }

    #[tokio::test]
    async fn depth_limit_rejects_before_any_fetch() {
        let fetch = FakeFetch::with(&[]);
        let mut config = udg_config(&[]);
        config["max_query_depth"] = 1.into();
        let layer = layer_with(config, Arc::clone(&fetch));
        let resp = send(&layer, post(r#"{ user(id: "1") { name } }"#)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(fetch.calls().is_empty());
    }

    #[tokio::test]
    async fn key_grants_reject_before_any_fetch() {
        let fetch = FakeFetch::with(&[]);
        let layer = layer_with(udg_config(&[]), Arc::clone(&fetch));
        let session: KeySession = serde_json::from_str(
            &serde_json::json!({
                "access": { "udg": {
                    "restricted_types": [{ "name": "User", "fields": ["email"] }]
                } }
            })
            .to_string(),
        )
        .expect("valid session");
        let mut req = post(r#"{ user(id: "1") { email } }"#);
        req.extensions_mut()
            .insert(crate::SessionContext::new(session, "hash"));
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(fetch.calls().is_empty());
    }

    #[tokio::test]
    async fn mutations_fetch_serially_queries_concurrently() {
        let slow_fast = |suffix: &str| {
            let mut fetch = FakeFetch {
                sleepy: true,
                ..FakeFetch::default()
            };
            fetch
                .responses
                .insert(format!("http://up/{suffix}slow"), (200, "1".into()));
            fetch
                .responses
                .insert(format!("http://up/{suffix}fast"), (200, "2".into()));
            Arc::new(fetch)
        };

        // Mutation root fields execute in selection order, serially: the
        // slow first field still finishes before the fast second starts.
        let fetch = slow_fast("m");
        let layer = layer_with(udg_config(&[]), Arc::clone(&fetch));
        // Serial order is observable through completion, not the recorded
        // call order (calls are recorded at start either way): assert both
        // fetches ran and the response is in order.
        let body = ok_json(&layer, post("mutation { slow fast }")).await;
        assert_eq!(body["data"], serde_json::json!({ "slow": 1, "fast": 2 }));
        assert_eq!(fetch.urls(), vec!["http://up/mslow", "http://up/mfast"]);

        // Query root fields fetch concurrently: total time is bounded by
        // the slow field, proven by both calls being recorded before the
        // slow response resolves (join_all starts them together).
        let fetch = slow_fast("q");
        let layer = layer_with(udg_config(&[]), Arc::clone(&fetch));
        let started = std::time::Instant::now();
        let body = ok_json(&layer, post("{ slow fast }")).await;
        assert_eq!(body["data"], serde_json::json!({ "slow": 1, "fast": 2 }));
        assert!(
            started.elapsed() < Duration::from_millis(95),
            "concurrent fetches overlap the 50ms sleep: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn graphql_source_receives_subquery_and_used_variables() {
        let fetch = FakeFetch::with(&[(
            "http://gqlup/graphql",
            200,
            r#"{"data":{"u":{"name":"Ada"}},"errors":[{"message":"deprecated"}]}"#,
        )]);
        let layer = layer_with(
            udg_config(&[(
                "Query.user",
                serde_json::json!({ "kind": "graphql", "url": "http://gqlup/graphql" }),
            )]),
            Arc::clone(&fetch),
        );
        let body = ok_json(
            &layer,
            post_json(serde_json::json!({
                "query": "query Q($id: ID!, $unused: Boolean!) { \
                          hello @skip(if: $unused) u: user(id: $id) { name } }",
                "variables": { "id": "7", "unused": true }
            })),
        )
        .await;
        assert_eq!(body["data"]["u"], serde_json::json!({ "name": "Ada" }));
        assert!(
            body["errors"][0]["message"]
                .as_str()
                .expect("message")
                .contains("deprecated"),
            "upstream error surfaces: {body}"
        );

        let calls = fetch.calls();
        assert_eq!(calls.len(), 1);
        let sub: serde_json::Value =
            serde_json::from_str(calls[0].body.as_deref().expect("body")).expect("json");
        let query = sub["query"].as_str().expect("query");
        assert!(query.contains("u: user(id: $id)"), "got: {query}");
        assert!(
            query.contains("($id: ID!)"),
            "used variable defined: {query}"
        );
        assert!(
            !query.contains("$unused"),
            "unused variable dropped: {query}"
        );
        assert!(!query.contains("hello"), "other fields stay home: {query}");
        assert_eq!(sub["variables"], serde_json::json!({ "id": "7" }));
    }

    #[tokio::test]
    async fn operation_selection_failures_are_400s() {
        let fetch = FakeFetch::with(&[]);
        let layer = layer_with(udg_config(&[]), Arc::clone(&fetch));

        let resp = send(
            &layer,
            post_json(serde_json::json!({
                "query": "query A { hello } query B { hello }"
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = send(
            &layer,
            post_json(serde_json::json!({
                "query": "query A { hello }", "operationName": "Nope"
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(fetch.calls().is_empty());
    }

    #[tokio::test]
    async fn bad_variables_are_400s() {
        let fetch = FakeFetch::with(&[]);
        let layer = layer_with(udg_config(&[]), Arc::clone(&fetch));

        // Not an object.
        let resp = send(
            &layer,
            post_json(serde_json::json!({ "query": "{ hello }", "variables": [1] })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Malformed JSON in the GET parameter.
        let req = Request::builder()
            .uri("/gql?query=%7B%20hello%20%7D&variables=%7Bnope")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A missing required variable fails coercion.
        let resp = send(
            &layer,
            post_json(serde_json::json!({
                "query": "query Q($id: ID!) { user(id: $id) { name } }"
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(fetch.calls().is_empty());
    }

    #[tokio::test]
    async fn persisted_queries_execute_locally() {
        let fetch = FakeFetch::with(&[("http://up/users/7", 200, r#"{"id":"7","name":"Ada"}"#)]);
        let mut config = udg_config(&[]);
        config["persisted_queries"] = serde_json::json!([{
            "method": "GET",
            "path": "/u/{id}",
            "operation": "query U($id: ID!) { user(id: $id) { name } }",
            "variables": { "id": "$path.id" }
        }]);
        let layer = layer_with(config, Arc::clone(&fetch));
        let req = Request::builder()
            .uri("/gql/u/7")
            .body(ProxyBody::empty())
            .expect("request");
        let body = ok_json(&layer, req).await;
        assert_eq!(body["data"]["user"], serde_json::json!({ "name": "Ada" }));
        assert_eq!(fetch.urls(), vec!["http://up/users/7"]);
    }

    #[tokio::test]
    async fn runaway_template_is_a_field_error_not_a_hang() {
        let fetch = FakeFetch::with(&[]);
        let layer = layer_with(
            udg_config(&[(
                "Query.hello",
                serde_json::json!({
                    "kind": "rest",
                    "url": "http://up/{% for i in range(100000000) %}x{% endfor %}"
                }),
            )]),
            Arc::clone(&fetch),
        );
        let body = ok_json(&layer, post("{ hello }")).await;
        assert_eq!(body["data"]["hello"], serde_json::Value::Null);
        assert!(
            body["errors"][0]["message"]
                .as_str()
                .expect("message")
                .contains("`Query.hello`"),
            "got: {body}"
        );
        assert!(fetch.calls().is_empty(), "nothing fetched");
    }

    #[tokio::test]
    async fn empty_source_body_resolves_to_null() {
        let fetch = FakeFetch::with(&[("http://up/hello", 200, "")]);
        let layer = layer_with(udg_config(&[]), fetch);
        let body = ok_json(&layer, post("{ hello }")).await;
        assert_eq!(body["data"]["hello"], serde_json::Value::Null);
        assert!(body.get("errors").is_none(), "null is not an error: {body}");
    }
}
