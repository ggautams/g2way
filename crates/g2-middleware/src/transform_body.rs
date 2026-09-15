//! [`BodyTransformLayer`]: per-API minijinja body transforms on
//! upstream-bound request bodies and client-bound response bodies
//! (milestone M8+, ADR-0007).
//!
//! The layer sits directly below the header transforms: gateway-generated
//! 401/403/429 rejections pass it untouched, while mock
//! responses and cached responses are transformed — the same contract as
//! [`transform_headers`](crate::transform_headers). Response rules match on
//! the *request's* method and path (a transform targets an endpoint, not a
//! status code) and skip `1xx` responses, so upgrade handshakes tunnel
//! through undisturbed.
//!
//! A matching body is buffered whole — requests bounded by the API's
//! `max_request_body_bytes` (else 1 MiB), responses by the block's
//! `max_response_body_bytes` — then replaced by the rendered template
//! output with a truthful `Content-Length` (`Transfer-Encoding` and
//! `Content-Encoding` are dropped; the rendered text is neither chunked nor
//! compressed). Upstream trailer frames survive a response transform, so
//! `grpc-status` stays intact.
//!
//! Transforms **fail closed** (ADR-0007): an over-cap body or failing
//! render answers `413`/`500` on the request side and `502` on the response
//! side rather than passing the original body through — transforms are
//! often used to redact, and failing open would leak exactly what the
//! configuration exists to remove. Rendering is pure computation bounded by
//! a fuel limit; there is no timeout machinery.
//!
//! Every template is compiled once at route-build time into a per-API
//! [`minijinja::Environment`]; the per-request work on matching traffic is
//! one buffered read plus one render of a prebuilt program (ADR-0001).
//! Non-matching traffic streams through with a regex search as the only
//! added cost.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use g2_core::body_transform::{BodyTransformRule, BodyTransforms};
use g2_core::Error;
use http::header::{HeaderMap, HeaderValue};
use http::{header, Method, Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full, Limited};
use minijinja::Environment;
use regex::Regex;
use tower::{Layer, Service};

use crate::response::json_error;
use crate::size_limit::is_over_limit;
use crate::{ProxyBody, SessionContext};

/// Bound on the buffered request body when the API sets no
/// `max_request_body_bytes` of its own: 1 MiB (the GraphQL layer's default).
const DEFAULT_MAX_BODY_BYTES: u64 = 1_048_576;

/// Fuel budget per render: bounds pathological templates (unbounded loops)
/// deterministically without any timeout machinery. Generously above what a
/// legitimate body-reshaping template consumes.
pub(crate) const RENDER_FUEL: u64 = 1_000_000;

/// One rule, precompiled: matching state plus the name its template is
/// registered under in the shared environment.
struct CompiledRule {
    pattern: Regex,
    /// Empty = every method.
    methods: Vec<Method>,
    /// `request[i]` / `response[i]` — the template's registry name and the
    /// rule's name in logs.
    name: String,
    content_type: HeaderValue,
}

impl CompiledRule {
    fn matches(&self, method: &Method, path: &str) -> bool {
        (self.methods.is_empty() || self.methods.contains(method)) && self.pattern.is_match(path)
    }
}

/// One API's compiled transform state, shared by every clone of the service.
struct TransformState {
    api_id: String,
    env: Environment<'static>,
    request: Vec<CompiledRule>,
    response: Vec<CompiledRule>,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl std::fmt::Debug for TransformState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransformState")
            .field("api_id", &self.api_id)
            .field("request", &self.request.len())
            .field("response", &self.response.len())
            .finish_non_exhaustive()
    }
}

impl TransformState {
    fn first_match<'a>(
        rules: &'a [CompiledRule],
        method: &Method,
        path: &str,
    ) -> Option<&'a CompiledRule> {
        rules.iter().find(|rule| rule.matches(method, path))
    }

    /// Renders `rule`'s template against `ctx`.
    fn render(&self, rule: &CompiledRule, ctx: minijinja::Value) -> Result<String, String> {
        self.env
            .get_template(&rule.name)
            .and_then(|template| template.render(ctx))
            .map_err(|err| err.to_string())
    }
}

/// Compiles one direction's rules into `state`-shaped parts, registering
/// each template in `env` under `{direction}[{index}]`.
fn compile_rules(
    env: &mut Environment<'static>,
    rules: &[BodyTransformRule],
    direction: &str,
    api_id: &str,
) -> Result<Vec<CompiledRule>, Error> {
    let fail = |reason: String| Error::InvalidApiDefinition {
        api: api_id.to_owned(),
        reason,
    };
    let mut compiled = Vec::with_capacity(rules.len());
    for (index, rule) in rules.iter().enumerate() {
        let name = format!("{direction}[{index}]");
        let pattern = Regex::new(&rule.pattern)
            .map_err(|err| fail(format!("invalid `transform_body.{name}` pattern: {err}")))?;
        let mut methods = Vec::with_capacity(rule.methods.len());
        for method in &rule.methods {
            methods.push(
                Method::from_bytes(method.to_ascii_uppercase().as_bytes()).map_err(|_| {
                    fail(format!(
                        "invalid `transform_body.{name}` method: `{method}`"
                    ))
                })?,
            );
        }
        let content_type = HeaderValue::from_str(&rule.content_type)
            .map_err(|_| fail(format!("invalid `transform_body.{name}` content type")))?;
        env.add_template_owned(name.clone(), rule.template.clone())
            .map_err(|err| fail(format!("invalid `transform_body.{name}` template: {err}")))?;
        compiled.push(CompiledRule {
            pattern,
            methods,
            name,
            content_type,
        });
    }
    Ok(compiled)
}

/// Tower layer applying one API's [`BodyTransforms`].
#[derive(Debug, Clone)]
pub struct BodyTransformLayer {
    state: Arc<TransformState>,
}

impl BodyTransformLayer {
    /// Compiles `cfg` into a layer: every pattern, method and template is
    /// precompiled here, at route-build time. `max_request_body_bytes` is
    /// the API's request-body cap (else 1 MiB); `api_id` names the API in
    /// errors and logs. Returns `Ok(None)` when the block declares no
    /// rules, leaving the API's chain unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a pattern, method,
    /// content type or template does not compile. Definitions are validated
    /// before routes are built, so this failing indicates a validation gap,
    /// but the route build surfaces it loudly rather than panicking.
    pub fn from_config(
        cfg: &BodyTransforms,
        max_request_body_bytes: Option<u64>,
        api_id: &str,
    ) -> Result<Option<Self>, Error> {
        if cfg.is_empty() {
            return Ok(None);
        }
        let mut env = Environment::new();
        // Bodies are not HTML; render templates verbatim.
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
        env.set_fuel(Some(RENDER_FUEL));
        let request = compile_rules(&mut env, &cfg.request, "request", api_id)?;
        let response = compile_rules(&mut env, &cfg.response, "response", api_id)?;
        let as_cap = |bytes: u64| usize::try_from(bytes).unwrap_or(usize::MAX);
        Ok(Some(Self {
            state: Arc::new(TransformState {
                api_id: api_id.to_owned(),
                env,
                request,
                response,
                max_request_bytes: as_cap(max_request_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES)),
                max_response_bytes: as_cap(cfg.max_response_body_bytes),
            }),
        }))
    }
}

impl<S> Layer<S> for BodyTransformLayer {
    type Service = BodyTransformer<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyTransformer {
            inner,
            state: Arc::clone(&self.state),
        }
    }
}

/// The [`Service`] produced by [`BodyTransformLayer`].
#[derive(Debug, Clone)]
pub struct BodyTransformer<S> {
    inner: S,
    state: Arc<TransformState>,
}

/// Request facts captured before the body is consumed, exposed to templates
/// as the `_g2` context object.
struct RequestMeta {
    method: Method,
    path: String,
    query: String,
    /// Lowercase request-header name → first value (lossy UTF-8).
    headers: serde_json::Value,
    session_alias: Option<String>,
}

impl RequestMeta {
    fn capture(req: &Request<ProxyBody>) -> Self {
        let mut headers = serde_json::Map::new();
        for name in req.headers().keys() {
            if let Some(value) = req.headers().get(name) {
                headers.insert(
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes())
                        .into_owned()
                        .into(),
                );
            }
        }
        Self {
            method: req.method().clone(),
            path: req.uri().path().to_owned(),
            query: req.uri().query().unwrap_or("").to_owned(),
            headers: serde_json::Value::Object(headers),
            session_alias: req
                .extensions()
                .get::<SessionContext>()
                .and_then(|ctx| ctx.session().alias.clone()),
        }
    }

    /// The template context for one buffered payload: `body` (parsed JSON,
    /// `none` when the payload is not valid JSON), `raw` (lossy UTF-8 text)
    /// and `_g2` (request metadata, plus `status` for response rules).
    fn render_context(&self, payload: &Bytes, status: Option<StatusCode>) -> minijinja::Value {
        let body: serde_json::Value =
            serde_json::from_slice(payload).unwrap_or(serde_json::Value::Null);
        let mut g2 = serde_json::json!({
            "method": self.method.as_str(),
            "path": self.path,
            "query": self.query,
            "headers": self.headers,
            "session": self
                .session_alias
                .as_ref()
                .map(|alias| serde_json::json!({ "alias": alias })),
        });
        if let Some(status) = status {
            g2["status"] = status.as_u16().into();
        }
        minijinja::Value::from_serialize(serde_json::json!({
            "body": body,
            "raw": String::from_utf8_lossy(payload),
            "_g2": g2,
        }))
    }
}

/// Sets the rebuilt message's framing headers: the rendered text is neither
/// chunked nor compressed, and its length is known exactly.
fn set_framing_headers(headers: &mut HeaderMap, content_type: &HeaderValue, len: usize) {
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::CONTENT_ENCODING);
    headers.insert(header::CONTENT_TYPE, content_type.clone());
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
}

impl<S> Service<Request<ProxyBody>> for BodyTransformer<S>
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
        let state = Arc::clone(&self.state);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let request_rule =
                TransformState::first_match(&state.request, req.method(), req.uri().path());
            let response_rule =
                TransformState::first_match(&state.response, req.method(), req.uri().path());
            if request_rule.is_none() && response_rule.is_none() {
                return inner.call(req).await;
            }
            let meta = RequestMeta::capture(&req);

            let req = if let Some(rule) = request_rule {
                let (mut parts, body) = req.into_parts();
                let payload = match Limited::new(body, state.max_request_bytes).collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(err) => {
                        return Ok(if is_over_limit(err.as_ref()) {
                            json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
                        } else {
                            json_error(StatusCode::BAD_REQUEST, "failed to read the request body")
                        });
                    }
                };
                let rendered = match state.render(rule, meta.render_context(&payload, None)) {
                    Ok(rendered) => Bytes::from(rendered),
                    Err(err) => {
                        tracing::error!(
                            api_id = %state.api_id,
                            rule = %rule.name,
                            error = %err,
                            "request body transform failed"
                        );
                        return Ok(json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "body transform failed",
                        ));
                    }
                };
                set_framing_headers(&mut parts.headers, &rule.content_type, rendered.len());
                Request::from_parts(parts, ProxyBody::new(Full::new(rendered)))
            } else {
                req
            };

            let resp = inner.call(req).await?;
            let Some(rule) = response_rule else {
                return Ok(resp);
            };
            // 1xx (upgrade handshakes included) carry no transformable body;
            // buffering one would break the tunnel.
            if resp.status().is_informational() {
                return Ok(resp);
            }
            let status = resp.status();
            let (mut parts, body) = resp.into_parts();
            let collected = match Limited::new(body, state.max_response_bytes).collect().await {
                Ok(collected) => collected,
                Err(err) => {
                    let message = if is_over_limit(err.as_ref()) {
                        "upstream response too large to transform"
                    } else {
                        "failed to read the upstream response body"
                    };
                    tracing::error!(
                        api_id = %state.api_id,
                        rule = %rule.name,
                        error = %err,
                        "response body transform failed"
                    );
                    return Ok(json_error(StatusCode::BAD_GATEWAY, message));
                }
            };
            let trailers = collected.trailers().cloned();
            let payload = collected.to_bytes();
            let rendered = match state.render(rule, meta.render_context(&payload, Some(status))) {
                Ok(rendered) => Bytes::from(rendered),
                Err(err) => {
                    tracing::error!(
                        api_id = %state.api_id,
                        rule = %rule.name,
                        error = %err,
                        "response body transform failed"
                    );
                    return Ok(json_error(StatusCode::BAD_GATEWAY, "body transform failed"));
                }
            };
            set_framing_headers(&mut parts.headers, &rule.content_type, rendered.len());
            Ok(Response::from_parts(
                parts,
                ProxyBody::new(BufferedBody {
                    data: Some(rendered),
                    trailers,
                }),
            ))
        })
    }
}

/// A fully buffered body: one data frame, then the preserved upstream
/// trailers (if any) — so a transformed gRPC response keeps `grpc-status`.
struct BufferedBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl Body for BufferedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(data) = this.data.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if let Some(trailers) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.as_ref().map_or(0, |data| data.len() as u64))
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::StreamBody;
    use tower::ServiceExt;

    use super::*;
    use crate::size_limit::RequestTooLarge;

    fn transforms(json: &str) -> BodyTransforms {
        serde_json::from_str(json).expect("valid transform JSON")
    }

    fn layer(json: &str) -> BodyTransformLayer {
        BodyTransformLayer::from_config(&transforms(json), None, "api")
            .expect("compiles")
            .expect("non-empty")
    }

    fn full_body(text: &str) -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::from(text.to_owned())))
    }

    async fn read_body(body: ProxyBody) -> String {
        let bytes = body.collect().await.expect("collect").to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    /// Inner service echoing the received request body and content headers
    /// back in a JSON envelope, so tests can see what the upstream would.
    async fn echo(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
        let content_length = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
        let chunked = req.headers().contains_key(header::TRANSFER_ENCODING);
        let body = read_body(req.into_body()).await;
        let envelope = serde_json::json!({
            "saw": body,
            "content_type": content_type,
            "content_length": content_length,
            "chunked": chunked,
        });
        Ok(Response::new(full_body(&envelope.to_string())))
    }

    async fn run(layer: &BodyTransformLayer, req: Request<ProxyBody>) -> Response<ProxyBody> {
        layer
            .clone()
            .layer(tower::service_fn(echo))
            .oneshot(req)
            .await
            .expect("infallible")
    }

    fn post(path: &str, body: &str) -> Request<ProxyBody> {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .body(full_body(body))
            .expect("request")
    }

    #[test]
    fn from_config_skips_empty_blocks() {
        let cfg: BodyTransforms = serde_json::from_str("{}").expect("parses");
        assert!(BodyTransformLayer::from_config(&cfg, None, "api")
            .expect("ok")
            .is_none());
    }

    #[tokio::test]
    async fn request_body_is_transformed_with_truthful_framing() {
        let layer = layer(
            r#"{"request": [{
                "pattern": "^/orders$",
                "template": "{\"wrapped\": {{ body.id }}, \"who\": \"{{ _g2.method }} {{ _g2.path }}\"}"
            }]}"#,
        );
        let resp = run(&layer, post("/orders", r#"{"id": 7}"#)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let envelope: serde_json::Value =
            serde_json::from_str(&read_body(resp.into_body()).await).expect("json");
        let saw = envelope["saw"].as_str().expect("saw");
        assert_eq!(saw, r#"{"wrapped": 7, "who": "POST /orders"}"#);
        assert_eq!(envelope["content_type"], "application/json");
        assert_eq!(envelope["content_length"], saw.len().to_string());
        assert_eq!(envelope["chunked"], false, "transfer-encoding stripped");
    }

    #[tokio::test]
    async fn context_exposes_headers_query_and_raw() {
        let layer = layer(
            r#"{"request": [{
                "pattern": "^/t$",
                "template": "{{ _g2.headers['x-tag'] }}|{{ _g2.query }}|{{ raw }}",
                "content_type": "text/plain"
            }]}"#,
        );
        let mut req = post("/t?a=1", "plain text");
        req.headers_mut()
            .insert("x-tag", HeaderValue::from_static("tagged"));
        let resp = run(&layer, req).await;
        let envelope: serde_json::Value =
            serde_json::from_str(&read_body(resp.into_body()).await).expect("json");
        assert_eq!(envelope["saw"], "tagged|a=1|plain text");
        assert_eq!(envelope["content_type"], "text/plain");
    }

    #[tokio::test]
    async fn non_json_body_renders_as_none_with_raw_available() {
        let layer = layer(
            r#"{"request": [{
                "pattern": "^/t$",
                "template": "{% if body %}json{% else %}{{ raw }}{% endif %}"
            }]}"#,
        );
        let resp = run(&layer, post("/t", "not json")).await;
        let envelope: serde_json::Value =
            serde_json::from_str(&read_body(resp.into_body()).await).expect("json");
        assert_eq!(envelope["saw"], "not json");
    }

    #[tokio::test]
    async fn session_alias_is_exposed_when_stamped() {
        let layer = layer(
            r#"{"request": [{
                "pattern": "^/t$",
                "template": "{% if _g2.session %}{{ _g2.session.alias }}{% else %}anon{% endif %}"
            }]}"#,
        );

        let resp = run(&layer, post("/t", "")).await;
        let envelope: serde_json::Value =
            serde_json::from_str(&read_body(resp.into_body()).await).expect("json");
        assert_eq!(envelope["saw"], "anon");

        let session = g2_core::KeySession {
            alias: Some("acme".into()),
            ..g2_core::KeySession::default()
        };
        let mut req = post("/t", "");
        req.extensions_mut()
            .insert(SessionContext::new(session, "hash"));
        let resp = run(&layer, req).await;
        let envelope: serde_json::Value =
            serde_json::from_str(&read_body(resp.into_body()).await).expect("json");
        assert_eq!(envelope["saw"], "acme");
    }

    #[tokio::test]
    async fn oversized_request_is_rejected_with_413() {
        let cfg = transforms(r#"{"request": [{"pattern": "^/t$", "template": "x"}]}"#);
        let layer = BodyTransformLayer::from_config(&cfg, Some(4), "api")
            .expect("compiles")
            .expect("non-empty");
        let resp = run(&layer, post("/t", "longer than four bytes")).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn mid_stream_size_limit_error_maps_to_413() {
        let layer = layer(r#"{"request": [{"pattern": "^/t$", "template": "x"}]}"#);
        let failing = ProxyBody::new(StreamBody::new(futures_util::stream::iter([Err::<
            Frame<Bytes>,
            crate::BoxError,
        >(
            Box::new(RequestTooLarge { limit: 4 }),
        )])));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/t")
            .body(failing)
            .expect("request");
        let resp = run(&layer, req).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn render_error_fails_closed_with_500() {
        // Iterating a non-iterable is a deterministic runtime (not syntax)
        // error.
        let layer = layer(
            r#"{"request": [{
                "pattern": "^/t$",
                "template": "{% for i in 42 %}x{% endfor %}"
            }]}"#,
        );
        let resp = run(&layer, post("/t", r#"{"other": 1}"#)).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn runaway_template_is_stopped_by_fuel() {
        let layer = layer(
            r#"{"request": [{
                "pattern": "^/t$",
                "template": "{% for i in range(10000) %}{% for j in range(10000) %}x{% endfor %}{% endfor %}"
            }]}"#,
        );
        let resp = run(&layer, post("/t", "")).await;
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "fuel exhaustion errors instead of hanging"
        );
    }

    #[tokio::test]
    async fn response_body_is_transformed_with_status_in_context() {
        let layer = layer(
            r#"{"response": [{
                "pattern": "^/t$",
                "template": "{\"status\": {{ _g2.status }}, \"saw\": {{ body.saw | tojson }}}"
            }]}"#,
        );
        let resp = run(&layer, post("/t", "hi")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).expect("ct"),
            "application/json"
        );
        let body: serde_json::Value =
            serde_json::from_str(&read_body(resp.into_body()).await).expect("json");
        assert_eq!(body["status"], 200);
        assert_eq!(body["saw"], "hi");
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_with_502() {
        let cfg = transforms(
            r#"{"response": [{"pattern": "^/t$", "template": "x"}],
                "max_response_body_bytes": 4}"#,
        );
        let layer = BodyTransformLayer::from_config(&cfg, None, "api")
            .expect("compiles")
            .expect("non-empty");
        let resp = run(&layer, post("/t", "")).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn response_render_error_fails_closed_with_502() {
        let layer = layer(
            r#"{"response": [{
                "pattern": "^/t$",
                "template": "{% for i in 42 %}x{% endfor %}"
            }]}"#,
        );
        let resp = run(&layer, post("/t", "not json")).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn upstream_trailers_survive_a_response_transform() {
        let layer = layer(r#"{"response": [{"pattern": "^/t$", "template": "done"}]}"#);
        let inner = tower::service_fn(|_req: Request<ProxyBody>| async {
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            let frames = [
                Ok::<_, crate::BoxError>(Frame::data(Bytes::from_static(b"payload"))),
                Ok(Frame::trailers(trailers)),
            ];
            let body = ProxyBody::new(StreamBody::new(futures_util::stream::iter(frames)));
            Ok::<_, Infallible>(Response::new(body))
        });
        let resp = layer
            .clone()
            .layer(inner)
            .oneshot(post("/t", ""))
            .await
            .expect("infallible");
        let collected = resp.into_body().collect().await.expect("collect");
        let trailers = collected.trailers().cloned();
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"done"));
        assert_eq!(
            trailers
                .expect("trailers kept")
                .get("grpc-status")
                .expect("grpc-status"),
            "0"
        );
    }

    #[tokio::test]
    async fn informational_responses_pass_untouched() {
        let layer = layer(r#"{"response": [{"pattern": "", "template": "never"}]}"#);
        let inner = tower::service_fn(|_req: Request<ProxyBody>| async {
            let resp = Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .body(ProxyBody::empty())
                .expect("response");
            Ok::<_, Infallible>(resp)
        });
        let resp = layer
            .clone()
            .layer(inner)
            .oneshot(post("/t", ""))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert!(read_body(resp.into_body()).await.is_empty());
    }

    #[tokio::test]
    async fn first_match_wins_and_methods_scope() {
        let layer = layer(
            r#"{"request": [
                {"pattern": "^/t$", "methods": ["PUT"], "template": "put"},
                {"pattern": "^/t$", "template": "first"},
                {"pattern": "^/t$", "template": "second"}
            ]}"#,
        );
        let resp = run(&layer, post("/t", "orig")).await;
        let envelope: serde_json::Value =
            serde_json::from_str(&read_body(resp.into_body()).await).expect("json");
        assert_eq!(
            envelope["saw"], "first",
            "PUT-scoped rule skipped, first POST match wins"
        );
    }

    #[tokio::test]
    async fn non_matching_traffic_streams_through_unchanged() {
        let layer = layer(r#"{"request": [{"pattern": "^/only-this$", "template": "x"}]}"#);
        let resp = run(&layer, post("/other", "untouched")).await;
        let envelope: serde_json::Value =
            serde_json::from_str(&read_body(resp.into_body()).await).expect("json");
        assert_eq!(envelope["saw"], "untouched");
        assert_eq!(envelope["content_type"], serde_json::Value::Null);
    }
}
