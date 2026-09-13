//! Per-request tracing spans.
//!
//! [`TraceLayer`] sits outermost in an API's chain and wraps every request
//! in a `tracing` span named after the route, carrying the fields an
//! operator filters traces by: `api_id`, `org_id`, method, path, response
//! status, and two fields recorded by deeper layers — `key_alias` (the auth
//! layer, once a session resolves) and `upstream_latency_ms` (the forwarding
//! service, around the upstream round trip).
//!
//! The span is an ordinary `tracing` span: with only the fmt subscriber it
//! enriches JSON log lines (events inside the request inherit its fields via
//! `with_current_span`); when the binary is started with an OTLP endpoint,
//! `g2-telemetry`'s OpenTelemetry bridge layer additionally exports it. The
//! `otel.*` fields are the bridge's conventions for span name, kind, and
//! status; other subscribers see them as ordinary fields.
//!
//! Spans exist only for routed requests: health endpoints and 404s never
//! enter a chain, so they produce no span.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{Request, Response};
use tower::{Layer, Service};
use tracing::instrument::Instrument as _;

use crate::context::RequestContext;
use crate::ProxyBody;

/// Name of the span field deeper layers record the authenticated key's
/// alias into (see [`AuthLayer`](crate::AuthLayer)).
pub const KEY_ALIAS_FIELD: &str = "key_alias";

/// Name of the span field the forwarding service records the upstream
/// round-trip latency (in milliseconds) into.
pub const UPSTREAM_LATENCY_FIELD: &str = "upstream_latency_ms";

/// Tower layer wrapping each of one API's requests in a `tracing` span.
#[derive(Debug, Clone)]
pub struct TraceLayer {
    ctx: RequestContext,
    span_name: Arc<str>,
}

impl TraceLayer {
    /// Builds the layer for the API identified by `ctx`; `span_name` becomes
    /// the exported span's name and should identify the route (its listen
    /// path), per the OTel convention of low-cardinality server span names.
    #[must_use]
    pub fn new(ctx: RequestContext, span_name: impl Into<Arc<str>>) -> Self {
        Self {
            ctx,
            span_name: span_name.into(),
        }
    }
}

impl<S> Layer<S> for TraceLayer {
    type Service = Trace<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Trace {
            inner,
            ctx: self.ctx.clone(),
            span_name: Arc::clone(&self.span_name),
        }
    }
}

/// The [`Service`] produced by [`TraceLayer`].
#[derive(Debug, Clone)]
pub struct Trace<S> {
    inner: S,
    ctx: RequestContext,
    span_name: Arc<str>,
}

impl<S> Service<Request<ProxyBody>> for Trace<S>
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
        let span = tracing::info_span!(
            "request",
            otel.name = %self.span_name,
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            http.request.method = %req.method(),
            url.path = %req.uri().path(),
            api_id = %self.ctx.api_id(),
            org_id = %self.ctx.org_id(),
            key_alias = tracing::field::Empty,
            http.response.status_code = tracing::field::Empty,
            upstream_latency_ms = tracing::field::Empty,
        );
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let recorder = span.clone();
        Box::pin(
            async move {
                let resp = inner.call(req).await?;
                recorder.record(
                    "http.response.status_code",
                    u64::from(resp.status().as_u16()),
                );
                // OTel semconv: a server span is an error only on 5xx — 4xx
                // is the client's problem, not a failing gateway.
                if resp.status().is_server_error() {
                    recorder.record("otel.status_code", "ERROR");
                }
                Ok(resp)
            }
            .instrument(span),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use bytes::Bytes;
    use http::StatusCode;
    use http_body_util::Full;
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    /// Captures every span field (at creation and via later `record`s) into
    /// a shared map, keyed by field name.
    #[derive(Debug, Default)]
    struct CaptureLayer {
        fields: Arc<Mutex<HashMap<String, String>>>,
    }

    struct Visitor<'a>(&'a Mutex<HashMap<String, String>>);

    impl tracing::field::Visit for Visitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0
                .lock()
                .expect("capture lock")
                .insert(field.name().to_owned(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0
                .lock()
                .expect("capture lock")
                .insert(field.name().to_owned(), value.to_owned());
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            attrs.record(&mut Visitor(&self.fields));
        }

        fn on_record(
            &self,
            _id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            values.record(&mut Visitor(&self.fields));
        }
    }

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    #[tokio::test]
    async fn span_records_route_identity_status_and_inner_layer_fields() {
        let capture = CaptureLayer::default();
        let fields = Arc::clone(&capture.fields);
        let subscriber = tracing_subscriber::registry().with(capture);

        // Inner service standing in for auth + forward: records the fields
        // those layers record through the current span, then answers 502.
        let inner = tower::service_fn(|_req: Request<ProxyBody>| async {
            let span = tracing::Span::current();
            span.record(KEY_ALIAS_FIELD, "acme-mobile-app");
            span.record(UPSTREAM_LATENCY_FIELD, 7_u64);
            let mut resp = Response::new(body());
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok::<_, Infallible>(resp)
        });
        let svc = TraceLayer::new(RequestContext::new("users-api", "acme"), "/users").layer(inner);

        let req = Request::builder()
            .method("GET")
            .uri("/users/42?x=1")
            .body(body())
            .expect("request");
        let resp = svc
            .oneshot(req)
            .with_subscriber(subscriber)
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let fields = fields.lock().expect("capture lock");
        let get = |k: &str| fields.get(k).cloned().unwrap_or_default();
        assert_eq!(get("otel.name"), "/users");
        assert_eq!(get("otel.kind"), "server");
        assert_eq!(get("api_id"), "users-api");
        assert_eq!(get("org_id"), "acme");
        assert_eq!(get("http.request.method"), "GET");
        assert_eq!(get("url.path"), "/users/42");
        assert_eq!(get("http.response.status_code"), "502");
        assert_eq!(get("otel.status_code"), "ERROR");
        assert_eq!(get(KEY_ALIAS_FIELD), "acme-mobile-app");
        assert_eq!(get(UPSTREAM_LATENCY_FIELD), "7");
    }

    #[tokio::test]
    async fn success_responses_leave_otel_status_unset() {
        let capture = CaptureLayer::default();
        let fields = Arc::clone(&capture.fields);
        let subscriber = tracing_subscriber::registry().with(capture);

        let inner = tower::service_fn(|_req: Request<ProxyBody>| async {
            Ok::<_, Infallible>(Response::new(body()))
        });
        let svc = TraceLayer::new(RequestContext::new("a", "o"), "/").layer(inner);
        svc.oneshot(Request::new(body()))
            .with_subscriber(subscriber)
            .await
            .expect("infallible");

        let fields = fields.lock().expect("capture lock");
        assert_eq!(
            fields.get("http.response.status_code").map(String::as_str),
            Some("200")
        );
        assert!(!fields.contains_key("otel.status_code"), "{fields:?}");
    }
}
