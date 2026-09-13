//! [`HeaderTransformLayer`]: per-API header add/remove on upstream-bound
//! requests and client-bound responses.
//!
//! The layer sits below auth and rate limiting in the chain, so transforms
//! apply only to traffic that reaches the forwarding stage: gateway-generated
//! 401/403/429 rejections pass it untouched, while upstream
//! responses — the forwarder's own 502/504 included — are transformed.
//!
//! The string-typed [`HeaderTransforms`] config is compiled into typed
//! [`HeaderName`]/[`HeaderValue`] pairs once at route-build time; per request
//! the only work is `HeaderMap` remove/insert with cheap (`Bytes`-backed)
//! clones (ADR-0001 hot-path rule).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use g2_core::transform::{HeaderTransform, HeaderTransforms};
use g2_core::Error;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response};
use tower::{Layer, Service};

use crate::ProxyBody;

/// One direction's rules, precompiled to typed names/values.
#[derive(Debug, Default)]
struct CompiledRules {
    remove: Vec<HeaderName>,
    add: Vec<(HeaderName, HeaderValue)>,
}

impl CompiledRules {
    fn compile(cfg: &HeaderTransform, api_id: &str) -> Result<Self, Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api_id.to_owned(),
            reason,
        };
        let mut remove = Vec::with_capacity(cfg.remove.len());
        for name in &cfg.remove {
            remove.push(
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| fail(format!("invalid header name in transform: `{name}`")))?,
            );
        }
        let mut add = Vec::with_capacity(cfg.add.len());
        for (name, value) in &cfg.add {
            add.push((
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| fail(format!("invalid header name in transform: `{name}`")))?,
                HeaderValue::from_str(value)
                    .map_err(|_| fail(format!("invalid header value in transform for `{name}`")))?,
            ));
        }
        Ok(Self { remove, add })
    }

    /// Removes first, then inserts (replacing), matching the config contract.
    fn apply(&self, headers: &mut HeaderMap) {
        for name in &self.remove {
            headers.remove(name);
        }
        for (name, value) in &self.add {
            headers.insert(name.clone(), value.clone());
        }
    }
}

/// Tower layer applying one API's [`HeaderTransforms`].
#[derive(Debug, Clone)]
pub struct HeaderTransformLayer {
    request: Arc<CompiledRules>,
    response: Arc<CompiledRules>,
}

impl HeaderTransformLayer {
    /// Compiles `cfg` into a layer; `api_id` names the API in errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a header name or value
    /// does not parse. Definitions are validated before routes are built, so
    /// this failing indicates a validation gap, but the route build surfaces
    /// it loudly rather than panicking.
    pub fn from_config(cfg: &HeaderTransforms, api_id: &str) -> Result<Self, Error> {
        Ok(Self {
            request: Arc::new(CompiledRules::compile(&cfg.request, api_id)?),
            response: Arc::new(CompiledRules::compile(&cfg.response, api_id)?),
        })
    }
}

impl<S> Layer<S> for HeaderTransformLayer {
    type Service = HeaderTransformer<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HeaderTransformer {
            inner,
            request: Arc::clone(&self.request),
            response: Arc::clone(&self.response),
        }
    }
}

/// The [`Service`] produced by [`HeaderTransformLayer`].
#[derive(Debug, Clone)]
pub struct HeaderTransformer<S> {
    inner: S,
    request: Arc<CompiledRules>,
    response: Arc<CompiledRules>,
}

impl<S> Service<Request<ProxyBody>> for HeaderTransformer<S>
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

    fn call(&mut self, mut req: Request<ProxyBody>) -> Self::Future {
        self.request.apply(req.headers_mut());
        let response = Arc::clone(&self.response);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let mut resp = inner.call(req).await?;
            response.apply(resp.headers_mut());
            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::Full;
    use tower::ServiceExt;

    use super::*;

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    fn transforms(json: &str) -> HeaderTransforms {
        serde_json::from_str(json).expect("valid transform JSON")
    }

    /// Inner service echoing every received request header back prefixed
    /// with `x-echo-`, plus fixed response headers to transform.
    async fn echo(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let mut resp = Response::new(body());
        for (name, value) in req.headers() {
            let echoed = format!("x-echo-{name}");
            resp.headers_mut().insert(
                HeaderName::from_bytes(echoed.as_bytes()).expect("test header"),
                value.clone(),
            );
        }
        resp.headers_mut()
            .insert("server", HeaderValue::from_static("upstream/1.0"));
        resp.headers_mut()
            .insert("x-upstream", HeaderValue::from_static("keep"));
        Ok(resp)
    }

    async fn run(cfg: &str, req: Request<ProxyBody>) -> Response<ProxyBody> {
        let layer = HeaderTransformLayer::from_config(&transforms(cfg), "api").expect("compiles");
        layer
            .layer(tower::service_fn(echo))
            .oneshot(req)
            .await
            .expect("infallible")
    }

    #[tokio::test]
    async fn request_headers_are_added_replaced_and_removed() {
        let cfg = r#"{"request": {
            "add": {"X-Env": "prod", "X-Replaced": "new"},
            "remove": ["X-Secret"]
        }}"#;
        let mut req = Request::new(body());
        req.headers_mut()
            .insert("x-secret", HeaderValue::from_static("leak"));
        req.headers_mut()
            .insert("x-replaced", HeaderValue::from_static("old"));
        req.headers_mut()
            .insert("x-kept", HeaderValue::from_static("kept"));

        let resp = run(cfg, req).await;
        let echoed = |name: &str| resp.headers().get(format!("x-echo-{name}")).cloned();
        assert_eq!(echoed("x-env").expect("added").as_bytes(), b"prod");
        assert_eq!(echoed("x-replaced").expect("replaced").as_bytes(), b"new");
        assert_eq!(echoed("x-kept").expect("untouched").as_bytes(), b"kept");
        assert!(echoed("x-secret").is_none(), "removed header reached inner");
    }

    #[tokio::test]
    async fn response_headers_are_added_and_removed() {
        let cfg = r#"{"response": {
            "add": {"X-Gateway": "g2way"},
            "remove": ["Server"]
        }}"#;
        let resp = run(cfg, Request::new(body())).await;
        assert_eq!(
            resp.headers().get("x-gateway").expect("added").as_bytes(),
            b"g2way"
        );
        assert!(resp.headers().get("server").is_none(), "server not removed");
        assert_eq!(
            resp.headers()
                .get("x-upstream")
                .expect("untouched")
                .as_bytes(),
            b"keep"
        );
    }

    #[tokio::test]
    async fn remove_then_add_of_the_same_name_ends_up_added() {
        let cfg = r#"{"response": {"add": {"Server": "g2way"}, "remove": ["Server"]}}"#;
        let resp = run(cfg, Request::new(body())).await;
        assert_eq!(
            resp.headers().get("server").expect("set").as_bytes(),
            b"g2way"
        );
    }

    #[test]
    fn from_config_rejects_unparseable_names() {
        let cfg = transforms(r#"{"request": {"remove": ["bad name\n"]}}"#);
        assert!(HeaderTransformLayer::from_config(&cfg, "api").is_err());
    }
}
