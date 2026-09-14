//! [`GraphQlLayer`]: GraphQL proxy-mode protections, the gateway-served
//! playground, and persisted GraphQL-as-REST endpoints (milestone M9,
//! ADR-0004).
//!
//! Sits **below** auth and rate limiting (protections need the key session,
//! the playground stays credentialed, and rejected requests never buy any
//! parse work) and **above** the header transforms (gateway rejections stay
//! untransformed like every other layer's, and the persisted-query rewrite
//! happens before request transforms see the upstream-bound request).
//!
//! Per request the layer:
//!
//! 1. Serves the GraphiQL playground page on its configured path (`GET`).
//! 2. Answers persisted GraphQL-as-REST endpoints: a matching REST-shaped
//!    request is rewritten into a `POST` of the pre-parsed operation to the
//!    API's GraphQL endpoint, with variables filled from path parameters
//!    and headers.
//! 3. Otherwise treats the request as a GraphQL request: the query (from a
//!    `GET` `?query=` parameter or a buffered JSON `POST` body) is parsed
//!    and validated against the API's schema, then policed — introspection
//!    control, depth limits, per-key field permissions — before the
//!    original bytes are forwarded upstream unchanged.
//!
//! Like [`transform_body`](crate::transform_body), this layer buffers a
//! request body. The buffering is bounded (the API's
//! `max_request_body_bytes`, else 1 MiB) and the exact bytes are
//! re-emitted, so the upstream sees the request unmodified; see ADR-0004
//! for the retry-semantics discussion.
//!
//! Everything derivable from configuration — the compiled schema, the
//! playground HTML, persisted-path regexes and pre-parsed operations — is
//! built once at route-build time (ADR-0001); the per-request work is
//! parsing the client's payload, which no gateway can precompute.
//!
//! # Error shapes
//!
//! Depth and introspection rejections answer `403` with the gateway's
//! plain `{"error": …}` shape; parse/validation failures and field
//! permission rejections answer `400` with a GraphQL-style
//! `{"errors": [{"message": …}]}` body — a deliberately mixed scheme,
//! each class answering in the shape its callers parse.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use apollo_compiler::executable::{ExecutableDocument, Selection, SelectionSet};
use apollo_compiler::validation::Valid;
use apollo_compiler::{Name, Schema};
use bytes::Bytes;
use g2_core::graphql::GraphQlConfig;
use g2_core::session::{ApiAccess, TypeFields};
use g2_core::{ApiDefinition, Error};
use http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use regex::Regex;
use tower::{Layer, Service};

use crate::response::json_error;
use crate::{ProxyBody, SessionContext};

/// Bound on the buffered GraphQL request body when the API sets no
/// `max_request_body_bytes` of its own: 1 MiB.
const DEFAULT_MAX_BODY_BYTES: u64 = 1_048_576;

/// The GraphiQL page served as the playground, with pinned CDN assets.
/// `__GRAPHQL_ENDPOINT__` is replaced with the API's endpoint at build time.
const PLAYGROUND_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>g2way GraphQL Playground</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/graphiql@3.7.1/graphiql.min.css" />
<style>body { margin: 0; } #graphiql { height: 100vh; }</style>
</head>
<body>
<div id="graphiql">Loading GraphiQL…</div>
<script crossorigin src="https://cdn.jsdelivr.net/npm/react@18.3.1/umd/react.production.min.js"></script>
<script crossorigin src="https://cdn.jsdelivr.net/npm/react-dom@18.3.1/umd/react-dom.production.min.js"></script>
<script crossorigin src="https://cdn.jsdelivr.net/npm/graphiql@3.7.1/graphiql.min.js"></script>
<script>
  ReactDOM.createRoot(document.getElementById('graphiql')).render(
    React.createElement(GraphiQL, {
      fetcher: GraphiQL.createFetcher({ url: '__GRAPHQL_ENDPOINT__' }),
      defaultEditorToolsVisibility: true,
    })
  );
</script>
</body>
</html>
"#;

/// Everything one API's GraphQL handling needs, precomputed at route-build
/// time.
struct GraphQlShared {
    api_id: String,
    schema: Valid<Schema>,
    introspection_enabled: bool,
    max_query_depth: Option<u32>,
    playground: Option<PlaygroundPage>,
    persisted: Vec<CompiledPersisted>,
    /// Origin-form URI persisted requests are rewritten to (the API's
    /// listen root, i.e. the GraphQL endpoint itself).
    graphql_uri: Uri,
    /// Bound on buffered request bodies, in bytes.
    max_body_bytes: usize,
}

impl std::fmt::Debug for GraphQlShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphQlShared")
            .field("api_id", &self.api_id)
            .field("introspection_enabled", &self.introspection_enabled)
            .field("max_query_depth", &self.max_query_depth)
            .field("persisted", &self.persisted.len())
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

/// The playground page, rendered once: its absolute serve path and HTML.
struct PlaygroundPage {
    path: String,
    html: Bytes,
}

/// One persisted GraphQL-as-REST endpoint, compiled for matching and
/// pre-parsed for enforcement.
struct CompiledPersisted {
    method: Method,
    /// Anchored regex over the absolute request path, with one named
    /// capture per `{name}` template parameter.
    regex: Regex,
    /// The raw operation text, forwarded to the upstream verbatim.
    query: String,
    /// The parsed operation — protections run on this without any
    /// per-request parsing.
    doc: Valid<ExecutableDocument>,
    operation_name: Option<String>,
    variables: Option<serde_json::Value>,
}

/// Tower layer enforcing one API's GraphQL configuration.
#[derive(Debug, Clone)]
pub struct GraphQlLayer {
    shared: Arc<GraphQlShared>,
}

/// Folds an apollo-compiler diagnostic list into per-diagnostic one-line
/// messages (the CLI-report `Display` form spans many lines of source
/// snippets — wrong for JSON error bodies).
fn diagnostic_messages(errors: &apollo_compiler::validation::DiagnosticList) -> Vec<String> {
    errors.iter().map(|d| d.error.to_string()).collect()
}

impl GraphQlLayer {
    /// Compiles the layer for one API from its validated definition:
    /// parses the schema, renders the playground page, and compiles every
    /// persisted endpoint's path regex and operation. Returns `Ok(None)`
    /// when the config is disabled, leaving the API's chain unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the schema or a
    /// persisted operation does not compile — normally impossible after
    /// [`GraphQlConfig::validate`], but route building must not panic on a
    /// definition that skipped validation.
    pub fn from_config(config: &GraphQlConfig, def: &ApiDefinition) -> Result<Option<Self>, Error> {
        if !config.enabled {
            return Ok(None);
        }
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: def.api_id.clone(),
            reason,
        };

        let schema = Schema::parse_and_validate(&config.schema, "schema.graphql").map_err(|e| {
            fail(format!(
                "`graphql.schema` is not a valid GraphQL schema: {}",
                diagnostic_messages(&e.errors).join("; ")
            ))
        })?;

        // `/users/` and `/users` both listen on the prefix `/users`; the
        // bare prefix is the API's GraphQL endpoint (`/` for a catch-all).
        let listen_prefix = def.listen_path.trim_end_matches('/');
        let endpoint = if listen_prefix.is_empty() {
            "/".to_owned()
        } else {
            listen_prefix.to_owned()
        };
        let graphql_uri: Uri = endpoint
            .parse()
            .map_err(|e| fail(format!("`listen_path` is not a valid URI path: {e}")))?;

        let playground = config.playground.as_ref().map(|pg| PlaygroundPage {
            path: format!("{listen_prefix}{}", pg.path),
            html: Bytes::from(PLAYGROUND_HTML.replace("__GRAPHQL_ENDPOINT__", &endpoint)),
        });

        let mut persisted = Vec::with_capacity(config.persisted_queries.len());
        for (index, pq) in config.persisted_queries.iter().enumerate() {
            let method = pq
                .method
                .to_ascii_uppercase()
                .parse::<Method>()
                .map_err(|_| {
                    fail(format!(
                        "`graphql.persisted_queries[{index}].method` is not a valid method"
                    ))
                })?;
            let mut pattern = format!("^{}", regex::escape(listen_prefix));
            for segment in pq.path.split('/').skip(1) {
                pattern.push('/');
                match segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                    Some(name) => {
                        pattern.push_str("(?P<");
                        pattern.push_str(name);
                        pattern.push_str(">[^/]+)");
                    }
                    None => pattern.push_str(&regex::escape(segment)),
                }
            }
            pattern.push('$');
            let regex = Regex::new(&pattern).map_err(|e| {
                fail(format!(
                    "`graphql.persisted_queries[{index}].path` does not compile: {e}"
                ))
            })?;
            let doc =
                ExecutableDocument::parse_and_validate(&schema, &pq.operation, "persisted.graphql")
                    .map_err(|e| {
                        fail(format!(
                            "`graphql.persisted_queries[{index}].operation` is not valid \
                             against the schema: {}",
                            diagnostic_messages(&e.errors).join("; ")
                        ))
                    })?;
            persisted.push(CompiledPersisted {
                method,
                regex,
                query: pq.operation.clone(),
                doc,
                operation_name: pq.operation_name.clone(),
                variables: pq.variables.clone(),
            });
        }

        Ok(Some(Self {
            shared: Arc::new(GraphQlShared {
                api_id: def.api_id.clone(),
                schema,
                introspection_enabled: config.introspection_enabled,
                max_query_depth: config.max_query_depth,
                playground,
                persisted,
                graphql_uri,
                max_body_bytes: usize::try_from(
                    def.max_request_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
                )
                .unwrap_or(usize::MAX),
            }),
        }))
    }
}

impl<S> Layer<S> for GraphQlLayer {
    type Service = GraphQl<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GraphQl {
            inner,
            shared: Arc::clone(&self.shared),
        }
    }
}

/// The [`Service`] produced by [`GraphQlLayer`].
#[derive(Debug, Clone)]
pub struct GraphQl<S> {
    inner: S,
    shared: Arc<GraphQlShared>,
}

impl<S> Service<Request<ProxyBody>> for GraphQl<S>
where
    S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ProxyBody>) -> Self::Future {
        let shared = Arc::clone(&self.shared);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            // 1. The playground page (already behind auth, which runs above).
            if let Some(pg) = &shared.playground {
                if req.method() == Method::GET && req.uri().path() == pg.path {
                    return Ok(playground_page(pg));
                }
            }

            // Per-key GraphQL grants. A keyless API, a bypassed path, or a
            // key with the all-APIs empty access map carries none — only
            // the API-level settings apply then.
            let grants: Option<ApiAccess> = req
                .extensions()
                .get::<SessionContext>()
                .and_then(|s| s.session().access.get(shared.api_id.as_str()).cloned());

            // 2. Persisted GraphQL-as-REST endpoints (first match wins).
            for p in &shared.persisted {
                if p.method != *req.method() {
                    continue;
                }
                let Some(caps) = p.regex.captures(req.uri().path()) else {
                    continue;
                };
                // The persisted operation is policed like a client query.
                if let Some(resp) = enforce(&shared, grants.as_ref(), &p.doc) {
                    return Ok(resp);
                }
                let variables = p
                    .variables
                    .as_ref()
                    .map(|t| substitute_variables(t, &caps, req.headers()));
                return inner
                    .call(rewrite_persisted(req, &shared, p, variables))
                    .await;
            }

            // 3. A plain GraphQL request: extract the query, validate,
            // police, forward the original bytes.
            let (query, req) = match extract_query(req, &shared).await {
                Ok(ok) => ok,
                Err(resp) => return Ok(resp),
            };
            let doc = match ExecutableDocument::parse_and_validate(
                &shared.schema,
                query,
                "request.graphql",
            ) {
                Ok(doc) => doc,
                Err(e) => {
                    return Ok(graphql_errors(
                        StatusCode::BAD_REQUEST,
                        diagnostic_messages(&e.errors),
                    ));
                }
            };
            if let Some(resp) = enforce(&shared, grants.as_ref(), &doc) {
                return Ok(resp);
            }
            inner.call(req).await
        })
    }
}

/// Serves the pre-rendered playground page.
fn playground_page(pg: &PlaygroundPage) -> Response<ProxyBody> {
    let mut resp = Response::new(ProxyBody::new(Full::new(pg.html.clone())));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

/// Builds a GraphQL-style error response: `{"errors": [{"message": …}, …]}`.
fn graphql_errors<I>(status: StatusCode, messages: I) -> Response<ProxyBody>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let errors: Vec<serde_json::Value> = messages
        .into_iter()
        .map(|m| serde_json::json!({ "message": m.into() }))
        .collect();
    let body = serde_json::json!({ "errors": errors }).to_string();
    let mut resp = Response::new(ProxyBody::new(Full::new(Bytes::from(body))));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Pulls the GraphQL query out of a request, returning it together with the
/// request to forward: untouched for `GET`, rebuilt around the buffered
/// body bytes for `POST` (so the upstream sees the exact original payload).
async fn extract_query(
    req: Request<ProxyBody>,
    shared: &GraphQlShared,
) -> Result<(String, Request<ProxyBody>), Response<ProxyBody>> {
    match *req.method() {
        // GraphQL over GET: the query rides the `query` parameter
        // (URL-encoded), the body stays untouched.
        Method::GET => match req.uri().query().and_then(query_parameter) {
            Some(query) if !query.trim().is_empty() => Ok((query, req)),
            _ => Err(graphql_errors(
                StatusCode::BAD_REQUEST,
                ["the request is missing a GraphQL query"],
            )),
        },
        Method::POST => {
            let (parts, body) = req.into_parts();
            let bytes = match Limited::new(body, shared.max_body_bytes).collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(err) => return Err(body_read_error(err.as_ref())),
            };
            #[derive(serde::Deserialize)]
            struct Envelope {
                query: Option<String>,
            }
            let envelope: Envelope = match serde_json::from_slice(&bytes) {
                Ok(envelope) => envelope,
                Err(e) => {
                    return Err(graphql_errors(
                        StatusCode::BAD_REQUEST,
                        [format!(
                            "the request body is not a valid GraphQL request: {e}"
                        )],
                    ));
                }
            };
            match envelope.query.filter(|q| !q.trim().is_empty()) {
                Some(query) => Ok((
                    query,
                    Request::from_parts(parts, ProxyBody::new(Full::new(bytes))),
                )),
                None => Err(graphql_errors(
                    StatusCode::BAD_REQUEST,
                    ["the request is missing a GraphQL query"],
                )),
            }
        }
        // A GraphQL endpoint only speaks GET and POST. (CORS preflights are
        // answered by the CORS layer, which runs above this one.)
        _ => Err(json_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "GraphQL requests must use GET or POST",
        )),
    }
}

/// Maps a body-collect failure: the size-limit layer's mid-stream
/// [`RequestTooLarge`](crate::size_limit::RequestTooLarge) and this layer's
/// own buffering cap ([`Limited`]) both answer `413`; anything else is a
/// client disconnect or transport error.
fn body_read_error(err: &(dyn std::error::Error + 'static)) -> Response<ProxyBody> {
    if crate::size_limit::is_over_limit(err) {
        json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
    } else {
        graphql_errors(StatusCode::BAD_REQUEST, ["failed to read the request body"])
    }
}

/// The percent-decoded `query` parameter of a raw query string, if present.
fn query_parameter(raw_query: &str) -> Option<String> {
    raw_query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == "query").then(|| percent_decode(value, true))
    })
}

/// Percent-decodes `s`; `plus_as_space` applies the query-string rule that
/// `+` encodes a space (never true for path segments, where `+` is
/// literal). Invalid escapes pass through verbatim.
fn percent_decode(s: &str, plus_as_space: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Runs the protection pipeline — introspection control, depth limit,
/// field permissions — over a validated document. `Some` carries the
/// rejection response; `None` means the document passed.
fn enforce(
    shared: &GraphQlShared,
    grants: Option<&ApiAccess>,
    doc: &Valid<ExecutableDocument>,
) -> Option<Response<ProxyBody>> {
    let introspection_allowed =
        shared.introspection_enabled && !grants.is_some_and(|g| g.disable_introspection);
    if !introspection_allowed && selects_introspection(doc) {
        return Some(json_error(
            StatusCode::FORBIDDEN,
            "introspection is disabled",
        ));
    }
    // A pure introspection document (every root field is a `__` meta field)
    // bypasses depth and field checks when introspection is allowed:
    // tooling sends deep introspection queries, and the schema is exactly
    // what introspection reveals — there is nothing left to hide.
    if is_pure_introspection(doc) {
        return None;
    }
    if let Some(limit) = effective_depth_limit(shared, grants) {
        if document_depth(doc) > limit {
            return Some(json_error(StatusCode::FORBIDDEN, "depth limit exceeded"));
        }
    }
    if let Some(grants) = grants {
        if let Some((ty, field)) = first_forbidden_field(doc, grants) {
            return Some(graphql_errors(
                StatusCode::BAD_REQUEST,
                [format!("field: {field} is restricted on type: {ty}")],
            ));
        }
    }
    None
}

/// The depth limit in force: a positive per-key override replaces the API
/// limit, a non-positive one (`-1`) lifts it, absence inherits it.
fn effective_depth_limit(shared: &GraphQlShared, grants: Option<&ApiAccess>) -> Option<u32> {
    match grants.and_then(|g| g.max_query_depth) {
        Some(n) if n > 0 => Some(u32::try_from(n).unwrap_or(u32::MAX)),
        Some(_) => None,
        None => shared.max_query_depth,
    }
}

/// All operations of a document, anonymous and named.
fn operations(
    doc: &ExecutableDocument,
) -> impl Iterator<Item = &apollo_compiler::executable::Operation> {
    doc.operations
        .anonymous
        .iter()
        .chain(doc.operations.named.values())
        .map(|node| &**node)
}

/// Whether any selection in the document (fragments included) is a
/// `__schema` or `__type` introspection field.
fn selects_introspection(doc: &ExecutableDocument) -> bool {
    fn walk(doc: &ExecutableDocument, set: &SelectionSet, visited: &mut HashSet<Name>) -> bool {
        set.selections.iter().any(|sel| match sel {
            Selection::Field(f) => {
                matches!(f.name.as_str(), "__schema" | "__type")
                    || walk(doc, &f.selection_set, visited)
            }
            Selection::InlineFragment(f) => walk(doc, &f.selection_set, visited),
            Selection::FragmentSpread(s) => {
                visited.insert(s.fragment_name.clone())
                    && doc
                        .fragments
                        .get(&s.fragment_name)
                        .is_some_and(|frag| walk(doc, &frag.selection_set, visited))
            }
        })
    }
    let mut visited = HashSet::new();
    operations(doc).any(|op| walk(doc, &op.selection_set, &mut visited))
}

/// Whether every root field of every operation (resolved through
/// fragments) is a `__` meta field — i.e. the document does nothing but
/// introspect.
fn is_pure_introspection(doc: &ExecutableDocument) -> bool {
    fn all_meta(doc: &ExecutableDocument, set: &SelectionSet, visited: &mut HashSet<Name>) -> bool {
        set.selections.iter().all(|sel| match sel {
            Selection::Field(f) => f.name.starts_with("__"),
            Selection::InlineFragment(f) => all_meta(doc, &f.selection_set, visited),
            Selection::FragmentSpread(s) => {
                !visited.insert(s.fragment_name.clone())
                    || doc
                        .fragments
                        .get(&s.fragment_name)
                        .is_some_and(|frag| all_meta(doc, &frag.selection_set, visited))
            }
        })
    }
    let mut visited = HashSet::new();
    operations(doc).all(|op| all_meta(doc, &op.selection_set, &mut visited))
}

/// The depth of the deepest operation: nested selection-set levels, so
/// `{ a { b } }` is 2. A fragment spread contributes its
/// body's depth at the spread site; fragment depths are memoized.
fn document_depth(doc: &ExecutableDocument) -> u32 {
    fn set_depth(
        doc: &ExecutableDocument,
        set: &SelectionSet,
        memo: &mut HashMap<Name, u32>,
        stack: &mut Vec<Name>,
    ) -> u32 {
        set.selections
            .iter()
            .map(|sel| match sel {
                Selection::Field(f) => 1 + set_depth(doc, &f.selection_set, memo, stack),
                Selection::InlineFragment(f) => set_depth(doc, &f.selection_set, memo, stack),
                Selection::FragmentSpread(s) => {
                    if let Some(depth) = memo.get(&s.fragment_name) {
                        return *depth;
                    }
                    // Cycle guard only: validation already rejects
                    // fragment cycles, so this is unreachable on a
                    // `Valid` document.
                    if stack.contains(&s.fragment_name) {
                        return 0;
                    }
                    let Some(frag) = doc.fragments.get(&s.fragment_name) else {
                        return 0;
                    };
                    stack.push(s.fragment_name.clone());
                    let depth = set_depth(doc, &frag.selection_set, memo, stack);
                    stack.pop();
                    memo.insert(s.fragment_name.clone(), depth);
                    depth
                }
            })
            .max()
            .unwrap_or(0)
    }
    let mut memo = HashMap::new();
    operations(doc)
        .map(|op| set_depth(doc, &op.selection_set, &mut memo, &mut Vec::new()))
        .max()
        .unwrap_or(0)
}

/// The first `(type, field)` selection the key's grants forbid, walking
/// every operation through fragments. `__` meta fields are never subject
/// to field permissions (introspection has its own control).
fn first_forbidden_field(doc: &ExecutableDocument, grants: &ApiAccess) -> Option<(String, String)> {
    fn walk(
        doc: &ExecutableDocument,
        set: &SelectionSet,
        grants: &ApiAccess,
        visited: &mut HashSet<Name>,
    ) -> Option<(String, String)> {
        for sel in &set.selections {
            match sel {
                Selection::Field(f) => {
                    let name = f.name.as_str();
                    if !name.starts_with("__") && !field_allowed(set.ty.as_str(), name, grants) {
                        return Some((set.ty.to_string(), name.to_owned()));
                    }
                    if let Some(hit) = walk(doc, &f.selection_set, grants, visited) {
                        return Some(hit);
                    }
                }
                Selection::InlineFragment(f) => {
                    if let Some(hit) = walk(doc, &f.selection_set, grants, visited) {
                        return Some(hit);
                    }
                }
                Selection::FragmentSpread(s) => {
                    if visited.insert(s.fragment_name.clone()) {
                        if let Some(frag) = doc.fragments.get(&s.fragment_name) {
                            if let Some(hit) = walk(doc, &frag.selection_set, grants, visited) {
                                return Some(hit);
                            }
                        }
                    }
                }
            }
        }
        None
    }
    let mut visited = HashSet::new();
    operations(doc).find_map(|op| walk(doc, &op.selection_set, grants, &mut visited))
}

/// Whether the grants permit selecting `field` on `ty`: a non-empty allow
/// list is exhaustive (and the block list is ignored — allow wins);
/// otherwise anything not block-listed passes. `"*"` matches
/// every field of its type.
fn field_allowed(ty: &str, field: &str, grants: &ApiAccess) -> bool {
    let listed = |list: &[TypeFields]| {
        list.iter()
            .any(|t| t.name == ty && t.fields.iter().any(|f| f == "*" || f == field))
    };
    if grants.allowed_types.is_empty() {
        !listed(&grants.restricted_types)
    } else {
        listed(&grants.allowed_types)
    }
}

/// Fills a persisted query's variables template: `"$path.<name>"` from the
/// matched path segments (percent-decoded), `"$header.<name>"` from
/// request headers (`null` when absent), recursing into nested containers.
fn substitute_variables(
    template: &serde_json::Value,
    caps: &regex::Captures<'_>,
    headers: &HeaderMap,
) -> serde_json::Value {
    use serde_json::Value;
    match template {
        Value::String(s) => {
            if let Some(name) = s.strip_prefix("$path.") {
                caps.name(name)
                    .map(|m| Value::String(percent_decode(m.as_str(), false)))
                    .unwrap_or(Value::Null)
            } else if let Some(name) = s.strip_prefix("$header.") {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| Value::String(v.to_owned()))
                    .unwrap_or(Value::Null)
            } else {
                template.clone()
            }
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| substitute_variables(v, caps, headers))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), substitute_variables(v, caps, headers)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Rewrites a matched persisted request into the upstream-bound GraphQL
/// `POST`: the method, path, and body are replaced; headers and extensions
/// (context, session, client address) are preserved.
fn rewrite_persisted(
    req: Request<ProxyBody>,
    shared: &GraphQlShared,
    p: &CompiledPersisted,
    variables: Option<serde_json::Value>,
) -> Request<ProxyBody> {
    let (mut parts, _rest_body) = req.into_parts();
    let mut envelope = serde_json::Map::new();
    envelope.insert("query".to_owned(), p.query.clone().into());
    if let Some(name) = &p.operation_name {
        envelope.insert("operationName".to_owned(), name.clone().into());
    }
    if let Some(variables) = variables {
        envelope.insert("variables".to_owned(), variables);
    }
    let bytes = Bytes::from(serde_json::Value::Object(envelope).to_string());

    parts.method = Method::POST;
    parts.uri = shared.graphql_uri.clone();
    parts.headers.remove(header::TRANSFER_ENCODING);
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    parts
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    Request::from_parts(parts, ProxyBody::new(Full::new(bytes)))
}

#[cfg(test)]
mod tests {
    use g2_core::KeySession;
    use http_body_util::StreamBody;
    use tower::ServiceExt;

    use super::*;
    use crate::size_limit::RequestTooLarge;
    use crate::BoxError;

    const SCHEMA: &str = "type Query { hello: String user(id: ID!): User } \
                          type User { id: ID! name: String email: String friend: User }";

    fn definition(graphql: serde_json::Value) -> ApiDefinition {
        serde_json::from_str(
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
        .expect("valid definition")
    }

    fn layer(graphql: serde_json::Value) -> GraphQlLayer {
        let def = definition(graphql);
        def.validate().expect("valid definition");
        GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def)
            .expect("compiles")
            .expect("enabled")
    }

    fn base_config() -> serde_json::Value {
        serde_json::json!({ "schema": SCHEMA })
    }

    /// Inner echo: drains the request body and mirrors it back, with the
    /// method, path, and content type in response headers.
    async fn echo(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let (parts, body) = req.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        let mut resp = Response::new(ProxyBody::new(Full::new(bytes)));
        resp.headers_mut().insert(
            "x-echo-method",
            parts.method.as_str().parse().expect("method value"),
        );
        resp.headers_mut()
            .insert("x-echo-path", parts.uri.path().parse().expect("path value"));
        if let Some(ct) = parts.headers.get(header::CONTENT_TYPE) {
            resp.headers_mut().insert("x-echo-content-type", ct.clone());
        }
        Ok(resp)
    }

    fn post(query: &str) -> Request<ProxyBody> {
        let body = serde_json::json!({ "query": query }).to_string();
        Request::builder()
            .method(Method::POST)
            .uri("/gql")
            .body(ProxyBody::new(Full::new(Bytes::from(body))))
            .expect("request")
    }

    /// A session whose `access["gql"]` grant is `grant`.
    fn session(grant: serde_json::Value) -> SessionContext {
        let session: KeySession =
            serde_json::from_str(&serde_json::json!({ "access": { "gql": grant } }).to_string())
                .expect("valid session");
        SessionContext::new(session, "hash")
    }

    async fn send(layer: &GraphQlLayer, req: Request<ProxyBody>) -> Response<ProxyBody> {
        layer
            .clone()
            .layer(tower::service_fn(echo))
            .oneshot(req)
            .await
            .expect("infallible")
    }

    async fn body_text(resp: Response<ProxyBody>) -> String {
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn valid_query_forwards_the_exact_bytes() {
        let layer = layer(base_config());
        let raw = r#"{ "query": "{ hello }", "variables": {"x": 1} }"#;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/gql")
            .body(ProxyBody::new(Full::new(Bytes::from_static(
                raw.as_bytes(),
            ))))
            .expect("request");
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_text(resp).await, raw, "upstream body byte-for-byte");
    }

    #[tokio::test]
    async fn get_queries_are_read_from_the_query_parameter() {
        let layer = layer(base_config());
        let req = Request::builder()
            .uri("/gql?query=%7B%20hello%20%7D") // "{ hello }"
            .body(ProxyBody::empty())
            .expect("request");
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Plus-as-space form works too.
        let req = Request::builder()
            .uri("/gql?query=%7B+hello+%7D")
            .body(ProxyBody::empty())
            .expect("request");
        assert_eq!(send(&layer, req).await.status(), StatusCode::OK);

        // A GET without a query is not a GraphQL request.
        let req = Request::builder()
            .uri("/gql")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn malformed_and_invalid_queries_are_rejected_with_graphql_errors() {
        let layer = layer(base_config());

        // Not JSON at all.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/gql")
            .body(ProxyBody::new(Full::new(Bytes::from_static(b"not json"))))
            .expect("request");
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("errors"));

        // Syntax error in the query.
        let resp = send(&layer, post("{ hello")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Unknown field: rejected by schema validation, never forwarded.
        let resp = send(&layer, post("{ nonexistent }")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let text = body_text(resp).await;
        assert!(text.contains("errors"), "got: {text}");

        // Fragments are resolved during validation and pass.
        let resp = send(
            &layer,
            post("query { user(id: \"1\") { ...f } } fragment f on User { name }"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_get_post_methods_are_rejected() {
        let layer = layer(base_config());
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/gql")
            .body(ProxyBody::empty())
            .expect("request");
        assert_eq!(
            send(&layer, req).await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[tokio::test]
    async fn depth_limit_is_enforced_with_selection_set_counting() {
        let mut cfg = base_config();
        cfg["max_query_depth"] = 2.into();
        let layer = layer(cfg);

        // Depth 2: at the limit, passes.
        let resp = send(&layer, post("{ user(id: \"1\") { name } }")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Depth 3: over the limit.
        let resp = send(&layer, post("{ user(id: \"1\") { friend { name } } }")).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_text(resp).await,
            r#"{"error":"depth limit exceeded"}"#,
            "documented error message"
        );

        // Fragment spreads count at the spread site (depth 3 via fragment).
        let resp = send(
            &layer,
            post("query { user(id: \"1\") { ...deep } } fragment deep on User { friend { name } }"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Inline fragments add no depth of their own.
        let resp = send(&layer, post("{ user(id: \"1\") { ... on User { name } } }")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn key_depth_overrides_replace_the_api_limit() {
        let mut cfg = base_config();
        cfg["max_query_depth"] = 2.into();
        let layer = layer(cfg);
        let deep = || post("{ user(id: \"1\") { friend { name } } }"); // depth 3

        // A larger key override admits what the API limit would reject.
        let mut req = deep();
        req.extensions_mut()
            .insert(session(serde_json::json!({ "max_query_depth": 5 })));
        assert_eq!(send(&layer, req).await.status(), StatusCode::OK);

        // A smaller key override tightens the limit.
        let mut req = post("{ user(id: \"1\") { name } }"); // depth 2
        req.extensions_mut()
            .insert(session(serde_json::json!({ "max_query_depth": 1 })));
        assert_eq!(send(&layer, req).await.status(), StatusCode::FORBIDDEN);

        // -1 lifts the limit entirely.
        let mut req = deep();
        req.extensions_mut()
            .insert(session(serde_json::json!({ "max_query_depth": -1 })));
        assert_eq!(send(&layer, req).await.status(), StatusCode::OK);

        // A key without an override inherits the API limit.
        let mut req = deep();
        req.extensions_mut().insert(session(serde_json::json!({})));
        assert_eq!(send(&layer, req).await.status(), StatusCode::FORBIDDEN);
    }

    const INTROSPECTION: &str = "{ __schema { queryType { name } } }";

    #[tokio::test]
    async fn introspection_control_works_at_api_and_key_level() {
        // Allowed by default — and a deep introspection query bypasses the
        // depth limit (there is nothing the schema does not already reveal).
        let mut cfg = base_config();
        cfg["max_query_depth"] = 1.into();
        let layer_on = layer(cfg);
        let resp = send(&layer_on, post(INTROSPECTION)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // `__typename` is a meta field, never introspection-blocked.
        let mut cfg = base_config();
        cfg["introspection_enabled"] = false.into();
        let layer_off = layer(cfg);
        let resp = send(&layer_off, post("{ __typename }")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // API-level off.
        let resp = send(&layer_off, post(INTROSPECTION)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_text(resp).await,
            r#"{"error":"introspection is disabled"}"#
        );

        // Key-level off on an API that allows it.
        let mut req = post(INTROSPECTION);
        req.extensions_mut().insert(session(
            serde_json::json!({ "disable_introspection": true }),
        ));
        assert_eq!(send(&layer_on, req).await.status(), StatusCode::FORBIDDEN);

        // `__type` is introspection too, through a fragment.
        let resp = send(
            &layer_off,
            post("query { ...f } fragment f on Query { __type(name: \"User\") { name } }"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn field_permissions_enforce_allow_and_block_lists() {
        let layer = layer(base_config());
        let user_email = || post("{ user(id: \"1\") { email } }");

        // Block list: the documented message, naming field and type.
        let mut req = user_email();
        req.extensions_mut().insert(session(serde_json::json!({
            "restricted_types": [{ "name": "User", "fields": ["email"] }]
        })));
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_text(resp).await,
            r#"{"errors":[{"message":"field: email is restricted on type: User"}]}"#
        );

        // Wildcard blocks every field of the type.
        let mut req = user_email();
        req.extensions_mut().insert(session(serde_json::json!({
            "restricted_types": [{ "name": "User", "fields": ["*"] }]
        })));
        assert_eq!(send(&layer, req).await.status(), StatusCode::BAD_REQUEST);

        // Allow list is exhaustive: unlisted fields are rejected…
        let allow_name_only = serde_json::json!({
            "allowed_types": [
                { "name": "Query", "fields": ["*"] },
                { "name": "User", "fields": ["name"] }
            ]
        });
        let mut req = user_email();
        req.extensions_mut()
            .insert(session(allow_name_only.clone()));
        assert_eq!(send(&layer, req).await.status(), StatusCode::BAD_REQUEST);

        // …and listed ones pass.
        let mut req = post("{ user(id: \"1\") { name } }");
        req.extensions_mut().insert(session(allow_name_only));
        assert_eq!(send(&layer, req).await.status(), StatusCode::OK);

        // A non-empty allow list wins: the block list is ignored.
        let mut req = user_email();
        req.extensions_mut().insert(session(serde_json::json!({
            "allowed_types": [
                { "name": "Query", "fields": ["*"] },
                { "name": "User", "fields": ["*"] }
            ],
            "restricted_types": [{ "name": "User", "fields": ["email"] }]
        })));
        assert_eq!(send(&layer, req).await.status(), StatusCode::OK);

        // Restrictions reach through fragments.
        let mut req = post("query { user(id: \"1\") { ...f } } fragment f on User { email }");
        req.extensions_mut().insert(session(serde_json::json!({
            "restricted_types": [{ "name": "User", "fields": ["email"] }]
        })));
        assert_eq!(send(&layer, req).await.status(), StatusCode::BAD_REQUEST);

        // No session (keyless / all-APIs grant): API-level checks only.
        assert_eq!(send(&layer, user_email()).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected_with_413() {
        // The layer's own cap (from max_request_body_bytes).
        let mut def = definition(base_config());
        def.max_request_body_bytes = Some(24);
        let layer = GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def)
            .expect("compiles")
            .expect("enabled");
        let resp = send(&layer, post("{ user(id: \"1\") { name } }")).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // A RequestTooLarge surfacing from the size-limit layer's counting
        // body below maps to 413 as well, not a 400/500.
        let layer = super::tests::layer(base_config());
        let frames = vec![Err::<http_body::Frame<Bytes>, BoxError>(Box::new(
            RequestTooLarge { limit: 10 },
        ))];
        let req = Request::builder()
            .method(Method::POST)
            .uri("/gql")
            .body(ProxyBody::new(StreamBody::new(futures_util::stream::iter(
                frames,
            ))))
            .expect("request");
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn playground_is_served_on_its_path() {
        let mut cfg = base_config();
        cfg["playground"] = serde_json::json!({});
        let layer = layer(cfg);

        let req = Request::builder()
            .uri("/gql/playground")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).expect("ct"),
            "text/html; charset=utf-8"
        );
        let html = body_text(resp).await;
        assert!(html.contains("GraphiQL"), "got: {html}");
        assert!(html.contains("url: '/gql'"), "endpoint substituted: {html}");

        // Other paths are handled as GraphQL, not as the playground.
        let req = Request::builder()
            .uri("/gql/other")
            .body(ProxyBody::empty())
            .expect("request");
        assert_eq!(send(&layer, req).await.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn persisted_queries_rewrite_matching_requests() {
        let mut cfg = base_config();
        cfg["persisted_queries"] = serde_json::json!([{
            "method": "GET",
            "path": "/users/{id}",
            "operation": "query User($id: ID!) { user(id: $id) { name } }",
            "variables": { "id": "$path.id", "trace": "$header.x-trace-id" }
        }]);
        let layer = layer(cfg);

        let req = Request::builder()
            .uri("/gql/users/42?ignored=1")
            .header("x-trace-id", "t-1")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-echo-method").expect("method"),
            "POST",
            "rewritten to a GraphQL POST"
        );
        assert_eq!(
            resp.headers().get("x-echo-path").expect("path"),
            "/gql",
            "sent to the API's GraphQL endpoint"
        );
        assert_eq!(
            resp.headers().get("x-echo-content-type").expect("ct"),
            "application/json"
        );
        let body: serde_json::Value =
            serde_json::from_str(&body_text(resp).await).expect("upstream body is JSON");
        assert_eq!(body["variables"]["id"], "42");
        assert_eq!(body["variables"]["trace"], "t-1");
        assert!(body["query"].as_str().expect("query").contains("user(id:"));

        // An absent header substitutes null.
        let req = Request::builder()
            .uri("/gql/users/7")
            .body(ProxyBody::empty())
            .expect("request");
        let body: serde_json::Value =
            serde_json::from_str(&body_text(send(&layer, req).await).await).expect("JSON");
        assert_eq!(body["variables"]["trace"], serde_json::Value::Null);

        // Non-matching method/path falls through to plain GraphQL handling.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/gql/users/42")
            .body(ProxyBody::new(Full::new(Bytes::from_static(
                br#"{"query": "{ hello }"}"#,
            ))))
            .expect("request");
        assert_eq!(send(&layer, req).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn persisted_operations_are_policed_like_client_queries() {
        let mut cfg = base_config();
        cfg["persisted_queries"] = serde_json::json!([{
            "method": "GET",
            "path": "/emails/{id}",
            "operation": "query User($id: ID!) { user(id: $id) { email } }",
            "variables": { "id": "$path.id" }
        }]);
        let layer = layer(cfg);

        let mut req = Request::builder()
            .uri("/gql/emails/42")
            .body(ProxyBody::empty())
            .expect("request");
        req.extensions_mut().insert(session(serde_json::json!({
            "restricted_types": [{ "name": "User", "fields": ["email"] }]
        })));
        let resp = send(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("restricted"));
    }

    #[tokio::test]
    async fn disabled_config_builds_no_layer() {
        let mut def = definition(base_config());
        def.graphql.as_mut().expect("set").enabled = false;
        assert!(
            GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def)
                .expect("compiles")
                .is_none()
        );
    }

    #[test]
    fn percent_decoding_handles_escapes_plus_and_junk() {
        assert_eq!(percent_decode("%7B%20a%20%7D", true), "{ a }");
        assert_eq!(percent_decode("a+b", true), "a b");
        assert_eq!(
            percent_decode("a+b", false),
            "a+b",
            "plus is literal in paths"
        );
        assert_eq!(
            percent_decode("100%", true),
            "100%",
            "trailing escape passes through"
        );
        assert_eq!(
            percent_decode("%zz", true),
            "%zz",
            "invalid escape passes through"
        );
    }
}
