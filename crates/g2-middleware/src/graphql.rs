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
//! 2. Recognizes subscription WebSocket handshakes (when
//!    `graphql.subscriptions` is enabled) and stamps the policed-tunnel
//!    extension the forwarder's upgrade path hands the connection to
//!    (see [`graphql_ws`](crate::graphql_ws), ADR-0009).
//! 3. Answers persisted GraphQL-as-REST endpoints: a matching REST-shaped
//!    request is rewritten into a `POST` of the pre-parsed operation to the
//!    API's GraphQL endpoint, with variables filled from path parameters
//!    and headers.
//! 4. Otherwise treats the request as a GraphQL request: the query (from a
//!    `GET` `?query=` parameter or a buffered JSON `POST` body) is parsed
//!    and validated against the API's schema, then policed — introspection
//!    control, depth limits, per-key field permissions — before the
//!    original bytes are forwarded upstream unchanged. A subscription
//!    operation over plain HTTP is rejected (`400`) — it can only execute
//!    over a WebSocket.
//!
//! In `udg` execution mode (ADR-0010) steps 3 and 4 do not forward: after
//! the same policing, the gateway executes the operation itself against
//! the API's data sources (the `graphql_udg` module, ADR-0010) and
//! `inner` is never called.
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
use apollo_compiler::response::{JsonMap, JsonValue};
use apollo_compiler::validation::Valid;
use apollo_compiler::{Name, Schema};
use bytes::Bytes;
use g2_core::graphql::{GraphQlConfig, GraphQlExecutionMode};
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
/// time. `pub(crate)` so [`graphql_sync`](crate::graphql_sync) can drive
/// the schema swap.
pub(crate) struct GraphQlShared {
    pub(crate) api_id: String,
    /// The schema-dependent state — the second designated swappable leaf
    /// after ADR-0006's `TargetSet` (ADR-0008): schema sync replaces it
    /// wholesale; everything else here is schema-independent and fixed
    /// until a reload.
    pub(crate) state: arc_swap::ArcSwap<GraphQlSchemaState>,
    /// Sync status/trigger state; `None` when `schema_sync` is not
    /// configured (the state is then never swapped).
    pub(crate) sync: Option<crate::graphql_sync::SchemaSync>,
    introspection_enabled: bool,
    max_query_depth: Option<u32>,
    playground: Option<PlaygroundPage>,
    pub(crate) persisted: Vec<CompiledPersisted>,
    /// Origin-form URI persisted requests are rewritten to (the API's
    /// listen root, i.e. the GraphQL endpoint itself).
    graphql_uri: Uri,
    /// Bound on buffered request bodies, in bytes.
    max_body_bytes: usize,
    /// Whether subscriptions over WebSocket are enabled (ADR-0009).
    subscriptions_enabled: bool,
    /// Cap on one client→gateway WebSocket message, in bytes.
    pub(crate) ws_max_message_bytes: usize,
    /// Universal Data Graph execution state; `Some` iff
    /// `execution_mode: "udg"` (ADR-0010). Schema-independent on purpose:
    /// udg mode rejects `schema_sync` at validation, so the schema leaf
    /// above never swaps for a UDG API.
    udg: Option<Arc<crate::graphql_udg::UdgEngine>>,
}

/// The schema-dependent half of [`GraphQlShared`], swapped wholesale by a
/// successful schema sync (seeded from `graphql.schema` at route build).
pub(crate) struct GraphQlSchemaState {
    /// The SDL this state was compiled from, for change detection.
    pub(crate) sdl: String,
    pub(crate) schema: Valid<Schema>,
    /// Each persisted operation validated against [`schema`](Self::schema),
    /// index-parallel to [`GraphQlShared::persisted`].
    pub(crate) persisted_docs: Vec<Valid<ExecutableDocument>>,
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

/// One persisted GraphQL-as-REST endpoint, compiled for matching. The
/// schema-independent half: the pre-parsed operation lives in
/// [`GraphQlSchemaState::persisted_docs`] (same index) because it must be
/// re-validated when a schema sync swaps the schema.
pub(crate) struct CompiledPersisted {
    method: Method,
    /// Anchored regex over the absolute request path, with one named
    /// capture per `{name}` template parameter.
    regex: Regex,
    /// The raw operation text, forwarded to the upstream verbatim (and
    /// re-validated against a synced schema).
    pub(crate) query: String,
    operation_name: Option<String>,
    variables: Option<serde_json::Value>,
}

/// Tower layer enforcing one API's GraphQL configuration.
#[derive(Debug, Clone)]
pub struct GraphQlLayer {
    pub(crate) shared: Arc<GraphQlShared>,
}

/// Folds an apollo-compiler diagnostic list into per-diagnostic one-line
/// messages (the CLI-report `Display` form spans many lines of source
/// snippets — wrong for JSON error bodies).
pub(crate) fn diagnostic_messages(
    errors: &apollo_compiler::validation::DiagnosticList,
) -> Vec<String> {
    errors.iter().map(|d| d.error.to_string()).collect()
}

impl GraphQlLayer {
    /// Compiles the layer for one API from its validated definition:
    /// parses the schema, renders the playground page, and compiles every
    /// persisted endpoint's path regex and operation. Returns `Ok(None)`
    /// when the config is disabled, leaving the API's chain unchanged.
    ///
    /// `udg_fetch` is the data-source HTTP seam (supplied by the proxy
    /// crate); it is required only when `execution_mode` is `udg`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the schema, a persisted
    /// operation, or a UDG data source does not compile — normally
    /// impossible after [`GraphQlConfig::validate`], but route building
    /// must not panic on a definition that skipped validation — or when
    /// `udg` mode is configured without a fetcher.
    pub fn from_config(
        config: &GraphQlConfig,
        def: &ApiDefinition,
        udg_fetch: Option<crate::SharedUdgFetch>,
    ) -> Result<Option<Self>, Error> {
        if !config.enabled {
            return Ok(None);
        }
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: def.api_id.clone(),
            reason,
        };

        let udg = match config.execution_mode {
            GraphQlExecutionMode::Proxy => None,
            GraphQlExecutionMode::Udg => {
                let fetch = udg_fetch.ok_or_else(|| {
                    fail(
                        "`udg` execution mode requires a data-source fetcher \
                          (not wired in this build path)"
                            .into(),
                    )
                })?;
                Some(Arc::new(crate::graphql_udg::UdgEngine::compile(
                    config, def, fetch,
                )?))
            }
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
        let mut persisted_docs = Vec::with_capacity(config.persisted_queries.len());
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
                operation_name: pq.operation_name.clone(),
                variables: pq.variables.clone(),
            });
            persisted_docs.push(doc);
        }

        Ok(Some(Self {
            shared: Arc::new(GraphQlShared {
                api_id: def.api_id.clone(),
                state: arc_swap::ArcSwap::from_pointee(GraphQlSchemaState {
                    sdl: config.schema.clone(),
                    schema,
                    persisted_docs,
                }),
                sync: config
                    .schema_sync
                    .as_ref()
                    .map(|c| crate::graphql_sync::SchemaSync::new(c.clone())),
                introspection_enabled: config.introspection_enabled,
                max_query_depth: config.max_query_depth,
                playground,
                persisted,
                graphql_uri,
                max_body_bytes: usize::try_from(
                    def.max_request_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
                )
                .unwrap_or(usize::MAX),
                subscriptions_enabled: config.subscriptions.as_ref().is_some_and(|s| s.enabled),
                ws_max_message_bytes: usize::try_from(
                    config
                        .subscriptions
                        .as_ref()
                        .and_then(|s| s.max_message_bytes)
                        .or(def.max_request_body_bytes)
                        .unwrap_or(DEFAULT_MAX_BODY_BYTES),
                )
                .unwrap_or(usize::MAX),
                udg,
            }),
        }))
    }

    /// A handle for driving this API's schema sync (`Some` iff
    /// `graphql.schema_sync` is configured) — the refresher task and the
    /// admin nudge listener act through it.
    #[must_use]
    pub fn sync_handle(&self) -> Option<crate::graphql_sync::GraphQlSyncHandle> {
        self.shared.sync.as_ref()?;
        Some(crate::graphql_sync::GraphQlSyncHandle {
            shared: Arc::clone(&self.shared),
        })
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
            // One load per request; the full `Arc` (not a guard) because it
            // is held across `.await`s (ADR-0006's swappable-leaf rule).
            let state = shared.state.load_full();

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

            // 2. A subscription WebSocket handshake (ADR-0009): stamp the
            // policed-tunnel extension and let the forwarder complete the
            // upgrade. Checked before the persisted loop so a persisted
            // `GET` route can never swallow a handshake.
            if crate::graphql_ws::is_websocket_handshake(&req) {
                if !shared.subscriptions_enabled {
                    return Ok(json_error(
                        StatusCode::BAD_REQUEST,
                        "GraphQL subscriptions are not enabled for this API",
                    ));
                }
                // Policing is the point: a socket speaking a subprotocol
                // the gateway does not understand would bypass every
                // GraphQL protection, so it is refused up front.
                if !crate::graphql_ws::offers_known_protocol(req.headers()) {
                    return Ok(json_error(
                        StatusCode::BAD_REQUEST,
                        "GraphQL subscriptions require the graphql-transport-ws or \
                         graphql-ws WebSocket subprotocol",
                    ));
                }
                let mut req = req;
                req.extensions_mut()
                    .insert(crate::graphql_ws::GraphQlWsTunnel::new(
                        Arc::clone(&shared),
                        grants,
                    ));
                return inner.call(req).await;
            }

            // 3. Persisted GraphQL-as-REST endpoints (first match wins).
            for (index, p) in shared.persisted.iter().enumerate() {
                if p.method != *req.method() {
                    continue;
                }
                let Some(caps) = p.regex.captures(req.uri().path()) else {
                    continue;
                };
                // The persisted operation is policed like a client query;
                // its doc rides the schema state (same index) because it is
                // re-validated whenever a schema sync swaps the schema.
                if let Some(resp) = enforce(&shared, grants.as_ref(), &state.persisted_docs[index])
                {
                    return Ok(resp);
                }
                let variables = p
                    .variables
                    .as_ref()
                    .map(|t| substitute_variables(t, &caps, req.headers()));
                // In udg mode the gateway executes the persisted operation
                // itself (ADR-0010); otherwise it is forwarded upstream.
                if let Some(udg) = &shared.udg {
                    let vars = match variables.map(JsonValue::from) {
                        Some(JsonValue::Object(map)) => map,
                        // Validation guarantees an object template.
                        _ => JsonMap::new(),
                    };
                    let meta = crate::graphql_udg::RequestMeta::capture(&req);
                    return Ok(crate::graphql_udg::execute(
                        udg,
                        &state,
                        &state.persisted_docs[index],
                        p.operation_name.as_deref(),
                        vars,
                        meta,
                    )
                    .await);
                }
                return inner
                    .call(rewrite_persisted(req, &shared, p, variables))
                    .await;
            }

            // 4. A plain GraphQL request: extract the query, validate,
            // police, then forward the original bytes (proxy mode) or
            // execute against the data sources (udg mode, ADR-0010).
            let ExtractedQuery {
                query,
                operation_name,
                variables,
                req,
            } = match extract_query(req, &shared).await {
                Ok(ok) => ok,
                Err(resp) => return Ok(resp),
            };
            let doc = match ExecutableDocument::parse_and_validate(
                &state.schema,
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
            // A subscription cannot execute over plain HTTP (ADR-0009);
            // rejected only when the *executed* operation resolves to one —
            // a multi-operation document whose selected operation is a
            // query still passes (ambiguous selection stays the upstream's
            // problem, as before).
            if doc
                .operations
                .get(operation_name.as_deref())
                .is_ok_and(|op| op.is_subscription())
            {
                return Ok(graphql_errors(
                    StatusCode::BAD_REQUEST,
                    ["GraphQL subscriptions require a WebSocket connection"],
                ));
            }
            if let Some(resp) = enforce(&shared, grants.as_ref(), &doc) {
                return Ok(resp);
            }
            if let Some(udg) = &shared.udg {
                let vars = match parse_raw_variables(variables) {
                    Ok(vars) => vars,
                    Err(resp) => return Ok(*resp),
                };
                let meta = crate::graphql_udg::RequestMeta::capture(&req);
                return Ok(crate::graphql_udg::execute(
                    udg,
                    &state,
                    &doc,
                    operation_name.as_deref(),
                    vars,
                    meta,
                )
                .await);
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
pub(crate) fn graphql_errors<I>(status: StatusCode, messages: I) -> Response<ProxyBody>
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

/// A GraphQL request pulled apart by [`extract_query`].
struct ExtractedQuery {
    query: String,
    operation_name: Option<String>,
    /// The request's variables, kept raw: proxy mode forwards the original
    /// bytes untouched, so these are parsed into a map only when the
    /// gateway itself executes (udg mode).
    variables: Option<RawVariables>,
    /// The request to forward: untouched for `GET`, rebuilt around the
    /// buffered body bytes for `POST`.
    req: Request<ProxyBody>,
}

/// Raw request variables: pre-parsed JSON when they rode a `POST` envelope,
/// URL-decoded text from a `GET` `?variables=` parameter.
enum RawVariables {
    Parsed(JsonValue),
    Text(String),
}

/// Maps raw variables to the executor's map shape: absent or JSON `null`
/// is the empty map, anything but an object is a `400` (udg mode only —
/// proxy mode never parses variables). The error response is boxed to keep
/// the happy-path return slim (clippy `result_large_err`).
fn parse_raw_variables(raw: Option<RawVariables>) -> Result<JsonMap, Box<Response<ProxyBody>>> {
    let value = match raw {
        None => return Ok(JsonMap::new()),
        Some(RawVariables::Parsed(value)) => value,
        Some(RawVariables::Text(text)) => match serde_json::from_str::<JsonValue>(&text) {
            Ok(value) => value,
            Err(e) => {
                return Err(Box::new(graphql_errors(
                    StatusCode::BAD_REQUEST,
                    [format!("`variables` is not valid JSON: {e}")],
                )));
            }
        },
    };
    match value {
        JsonValue::Null => Ok(JsonMap::new()),
        JsonValue::Object(map) => Ok(map),
        _ => Err(Box::new(graphql_errors(
            StatusCode::BAD_REQUEST,
            ["`variables` must be a JSON object"],
        ))),
    }
}

/// Pulls the GraphQL query (with the selected `operationName` and raw
/// variables, if any) out of a request.
async fn extract_query(
    req: Request<ProxyBody>,
    shared: &GraphQlShared,
) -> Result<ExtractedQuery, Response<ProxyBody>> {
    match *req.method() {
        // GraphQL over GET: the query rides the `query` parameter
        // (URL-encoded), the body stays untouched.
        Method::GET => {
            let query = req
                .uri()
                .query()
                .and_then(|raw| query_parameter(raw, "query"));
            match query {
                Some(query) if !query.trim().is_empty() => {
                    let operation_name = req
                        .uri()
                        .query()
                        .and_then(|raw| query_parameter(raw, "operationName"))
                        .filter(|n| !n.is_empty());
                    let variables = req
                        .uri()
                        .query()
                        .and_then(|raw| query_parameter(raw, "variables"))
                        .filter(|v| !v.trim().is_empty())
                        .map(RawVariables::Text);
                    Ok(ExtractedQuery {
                        query,
                        operation_name,
                        variables,
                        req,
                    })
                }
                _ => Err(graphql_errors(
                    StatusCode::BAD_REQUEST,
                    ["the request is missing a GraphQL query"],
                )),
            }
        }
        Method::POST => {
            let (parts, body) = req.into_parts();
            let bytes = match Limited::new(body, shared.max_body_bytes).collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(err) => return Err(body_read_error(err.as_ref())),
            };
            #[derive(serde::Deserialize)]
            struct Envelope {
                query: Option<String>,
                #[serde(rename = "operationName")]
                operation_name: Option<String>,
                variables: Option<JsonValue>,
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
                Some(query) => Ok(ExtractedQuery {
                    query,
                    operation_name: envelope.operation_name.filter(|n| !n.is_empty()),
                    variables: envelope.variables.map(RawVariables::Parsed),
                    req: Request::from_parts(parts, ProxyBody::new(Full::new(bytes))),
                }),
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

/// The percent-decoded `name` parameter of a raw query string, if present.
fn query_parameter(raw_query: &str, name: &str) -> Option<String> {
    raw_query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| percent_decode(value, true))
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

/// A protection-pipeline rejection: which check a document failed. Shared
/// by the HTTP path (mapped to a response by [`enforce`]) and the
/// subscription WebSocket relay (mapped to a protocol `error` message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Violation {
    /// The document introspects while introspection is disabled.
    Introspection,
    /// The document is deeper than the effective depth limit.
    DepthLimit,
    /// The key's grants forbid selecting `field` on `ty`.
    ForbiddenField {
        /// The parent type of the forbidden selection.
        ty: String,
        /// The forbidden field name.
        field: String,
    },
}

impl Violation {
    /// The client-facing message for this violation.
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Introspection => "introspection is disabled".into(),
            Self::DepthLimit => "depth limit exceeded".into(),
            Self::ForbiddenField { ty, field } => {
                format!("field: {field} is restricted on type: {ty}")
            }
        }
    }
}

/// Runs the protection pipeline — introspection control, depth limit,
/// field permissions — over a validated document.
///
/// # Errors
///
/// Returns the first [`Violation`] the document commits.
pub(crate) fn check_document(
    shared: &GraphQlShared,
    grants: Option<&ApiAccess>,
    doc: &Valid<ExecutableDocument>,
) -> Result<(), Violation> {
    let introspection_allowed =
        shared.introspection_enabled && !grants.is_some_and(|g| g.disable_introspection);
    if !introspection_allowed && selects_introspection(doc) {
        return Err(Violation::Introspection);
    }
    // A pure introspection document (every root field is a `__` meta field)
    // bypasses depth and field checks when introspection is allowed:
    // tooling sends deep introspection queries, and the schema is exactly
    // what introspection reveals — there is nothing left to hide.
    if is_pure_introspection(doc) {
        return Ok(());
    }
    if let Some(limit) = effective_depth_limit(shared, grants) {
        if document_depth(doc) > limit {
            return Err(Violation::DepthLimit);
        }
    }
    if let Some(grants) = grants {
        if let Some((ty, field)) = first_forbidden_field(doc, grants) {
            return Err(Violation::ForbiddenField { ty, field });
        }
    }
    Ok(())
}

/// [`check_document`] mapped to HTTP: depth/introspection violations answer
/// `403` with the plain error shape, field violations `400` with the
/// GraphQL error shape (ADR-0004). `None` means the document
/// passed.
fn enforce(
    shared: &GraphQlShared,
    grants: Option<&ApiAccess>,
    doc: &Valid<ExecutableDocument>,
) -> Option<Response<ProxyBody>> {
    match check_document(shared, grants, doc) {
        Ok(()) => None,
        Err(violation @ (Violation::Introspection | Violation::DepthLimit)) => {
            Some(json_error(StatusCode::FORBIDDEN, &violation.message()))
        }
        Err(violation @ Violation::ForbiddenField { .. }) => Some(graphql_errors(
            StatusCode::BAD_REQUEST,
            [violation.message()],
        )),
    }
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
        GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def, None)
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
        let layer = GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def, None)
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
            GraphQlLayer::from_config(def.graphql.as_ref().expect("set"), &def, None)
                .expect("compiles")
                .is_none()
        );
    }

    const SUB_SCHEMA: &str = "type Query { hello: String } \
                              type Subscription { ticks: Int }";

    fn subscriptions_config() -> serde_json::Value {
        serde_json::json!({ "schema": SUB_SCHEMA, "subscriptions": {} })
    }

    fn ws_handshake(protocols: Option<&str>) -> Request<ProxyBody> {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri("/gql")
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket");
        if let Some(protocols) = protocols {
            builder = builder.header(header::SEC_WEBSOCKET_PROTOCOL, protocols);
        }
        builder.body(ProxyBody::empty()).expect("request")
    }

    #[tokio::test]
    async fn ws_handshake_without_subscriptions_is_rejected() {
        let layer = layer(base_config());
        let resp = send(&layer, ws_handshake(Some("graphql-transport-ws"))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            body_text(resp).await.contains("not enabled"),
            "names the missing opt-in"
        );
    }

    #[tokio::test]
    async fn ws_handshake_requires_a_known_subprotocol() {
        let layer = layer(subscriptions_config());
        for offer in [None, Some("soap-over-ws")] {
            let resp = send(&layer, ws_handshake(offer)).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "offer {offer:?}");
            assert!(
                body_text(resp).await.contains("graphql-transport-ws"),
                "error names the supported subprotocols"
            );
        }
    }

    #[tokio::test]
    async fn ws_handshake_stamps_the_tunnel_extension_and_passes_through() {
        let layer = layer(subscriptions_config());
        let inner = tower::service_fn(|req: Request<ProxyBody>| async move {
            assert!(
                req.extensions()
                    .get::<crate::graphql_ws::GraphQlWsTunnel>()
                    .is_some(),
                "the tunnel extension must ride the forwarded handshake"
            );
            Ok::<_, Infallible>(Response::new(ProxyBody::empty()))
        });
        let resp = layer
            .clone()
            .layer(inner)
            .oneshot(ws_handshake(Some("graphql-ws, graphql-transport-ws")))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn subscriptions_over_plain_http_are_rejected() {
        let layer = layer(subscriptions_config());
        let resp = send(&layer, post("subscription { ticks }")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            body_text(resp).await.contains("WebSocket"),
            "points the client at WebSocket"
        );
    }

    #[tokio::test]
    async fn operation_name_selects_what_is_executed_over_http() {
        let layer = layer(subscriptions_config());
        let doc = "query Q { hello } subscription S { ticks }";

        // The selected operation is a query: passes.
        let body = serde_json::json!({ "query": doc, "operationName": "Q" }).to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/gql")
            .body(ProxyBody::new(Full::new(Bytes::from(body))))
            .expect("request");
        assert_eq!(send(&layer, req).await.status(), StatusCode::OK);

        // The selected operation is the subscription: rejected.
        let body = serde_json::json!({ "query": doc, "operationName": "S" }).to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/gql")
            .body(ProxyBody::new(Full::new(Bytes::from(body))))
            .expect("request");
        assert_eq!(send(&layer, req).await.status(), StatusCode::BAD_REQUEST);

        // Same selection over GET's operationName parameter.
        let req = Request::builder()
            .uri("/gql?query=query+Q+%7B+hello+%7D+subscription+S+%7B+ticks+%7D&operationName=S")
            .body(ProxyBody::empty())
            .expect("request");
        assert_eq!(send(&layer, req).await.status(), StatusCode::BAD_REQUEST);
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
