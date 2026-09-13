//! [`MockResponseLayer`]: per-API mock responses answered by the gateway
//! without contacting the upstream.
//!
//! Sits **below** auth/rate limiting (a protected API's mocks require
//! credentials and consume rate — pair a mock with an `ignore_auth_paths`
//! rule when it should be public) and **above** the forwarder, below the
//! header-transform layer so mock responses get the API's response
//! transforms like any upstream response would.
//!
//! Rules are tried in order; the first whose pattern (and optional method
//! filter) matches wins. The response is exactly the configured status,
//! headers and body: no content type is implied. Everything is precompiled
//! at route-build time — per request the match runs prebuilt automata and a
//! hit clones cheap `Bytes`/`HeaderValue` handles (ADR-0001 hot-path rule).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use g2_core::{Error, MockResponse};
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use regex::Regex;
use tower::{Layer, Service};

use crate::ProxyBody;

/// One mock rule, precompiled: prebuilt regex, typed status/headers, and
/// the body as shared [`Bytes`].
#[derive(Debug)]
struct CompiledMock {
    regex: Regex,
    /// Methods the rule applies to; empty = every method.
    methods: Vec<Method>,
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
}

impl CompiledMock {
    fn compile(rule: &MockResponse, api_id: &str) -> Result<Self, Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api_id.to_owned(),
            reason,
        };
        let regex = Regex::new(&rule.pattern)
            .map_err(|e| fail(format!("invalid mock regex `{}`: {e}", rule.pattern)))?;
        let methods = rule
            .methods
            .iter()
            .map(|m| {
                Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                    .map_err(|_| fail(format!("invalid mock method `{m}`")))
            })
            .collect::<Result<_, _>>()?;
        let status = StatusCode::from_u16(rule.status)
            .map_err(|_| fail(format!("invalid mock status `{}`", rule.status)))?;
        let headers = rule
            .headers
            .iter()
            .map(|(name, value)| {
                Ok((
                    HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| fail(format!("invalid mock header name `{name}`")))?,
                    HeaderValue::from_str(value)
                        .map_err(|_| fail(format!("invalid mock header value for `{name}`")))?,
                ))
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self {
            regex,
            methods,
            status,
            headers,
            body: Bytes::from(rule.body.clone()),
        })
    }

    fn matches(&self, method: &Method, path: &str) -> bool {
        (self.methods.is_empty() || self.methods.contains(method)) && self.regex.is_match(path)
    }

    fn response(&self) -> Response<ProxyBody> {
        let mut resp = Response::new(ProxyBody::new(Full::new(self.body.clone())));
        *resp.status_mut() = self.status;
        for (name, value) in &self.headers {
            resp.headers_mut().insert(name.clone(), value.clone());
        }
        resp
    }
}

/// Tower layer answering matching requests from one API's mock rules.
#[derive(Debug, Clone)]
pub struct MockResponseLayer {
    rules: Arc<Vec<CompiledMock>>,
}

impl MockResponseLayer {
    /// Compiles `rules` into a layer, or `None` when there are none (the
    /// API gets no mock layer at all); `api_id` names the API in errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a pattern, method,
    /// status, or header does not compile. Definitions are validated before
    /// routes are built, so this failing indicates a validation gap, but
    /// the route build surfaces it loudly rather than panicking.
    pub fn from_config(rules: &[MockResponse], api_id: &str) -> Result<Option<Self>, Error> {
        if rules.is_empty() {
            return Ok(None);
        }
        let compiled = rules
            .iter()
            .map(|r| CompiledMock::compile(r, api_id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(Self {
            rules: Arc::new(compiled),
        }))
    }
}

impl<S> Layer<S> for MockResponseLayer {
    type Service = Mock<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Mock {
            inner,
            rules: Arc::clone(&self.rules),
        }
    }
}

/// The [`Service`] produced by [`MockResponseLayer`].
#[derive(Debug, Clone)]
pub struct Mock<S> {
    inner: S,
    rules: Arc<Vec<CompiledMock>>,
}

impl<S> Service<Request<ProxyBody>> for Mock<S>
where
    S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ProxyBody>) -> Self::Future {
        let hit = self
            .rules
            .iter()
            .find(|r| r.matches(req.method(), req.uri().path()));
        match hit {
            Some(rule) => Box::pin(std::future::ready(Ok(rule.response()))),
            None => Box::pin(self.inner.call(req)),
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    fn rules(json: &str) -> Vec<MockResponse> {
        serde_json::from_str(json).expect("valid mock JSON")
    }

    /// Inner stand-in for the forwarder: 200 with a marker header.
    async fn upstream(_req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let mut resp = Response::new(body());
        resp.headers_mut()
            .insert("x-upstream", HeaderValue::from_static("1"));
        Ok(resp)
    }

    async fn call(json: &str, method: &str, path: &str) -> Response<ProxyBody> {
        let layer = MockResponseLayer::from_config(&rules(json), "api")
            .expect("compiles")
            .expect("non-empty config");
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(body())
            .expect("request");
        layer
            .layer(tower::service_fn(upstream))
            .oneshot(req)
            .await
            .expect("infallible")
    }

    #[test]
    fn empty_config_builds_no_layer() {
        assert!(MockResponseLayer::from_config(&[], "api")
            .expect("ok")
            .is_none());
    }

    #[tokio::test]
    async fn matching_request_gets_the_mock_not_the_upstream() {
        let cfg = r#"[{
            "pattern": "^/v1/ping$",
            "status": 418,
            "body": "pong",
            "headers": {"Content-Type": "text/plain"}
        }]"#;
        let resp = call(cfg, "GET", "/v1/ping").await;
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
        assert!(!resp.headers().contains_key("x-upstream"), "hit upstream");
        assert_eq!(
            resp.headers().get("content-type").expect("ct").as_bytes(),
            b"text/plain"
        );
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(bytes.as_ref(), b"pong");
    }

    #[tokio::test]
    async fn non_matching_requests_reach_the_upstream() {
        let cfg = r#"[{"pattern": "^/v1/ping$", "methods": ["GET"]}]"#;
        for (method, path) in [("GET", "/v1/other"), ("POST", "/v1/ping")] {
            let resp = call(cfg, method, path).await;
            assert!(
                resp.headers().contains_key("x-upstream"),
                "{method} {path} was mocked"
            );
        }
    }

    #[tokio::test]
    async fn first_matching_rule_wins() {
        let cfg = r#"[
            {"pattern": "^/v1/a$", "status": 201},
            {"pattern": "^/v1/", "status": 202}
        ]"#;
        assert_eq!(
            call(cfg, "GET", "/v1/a").await.status(),
            StatusCode::CREATED
        );
        assert_eq!(
            call(cfg, "GET", "/v1/b").await.status(),
            StatusCode::ACCEPTED
        );
    }

    #[tokio::test]
    async fn default_mock_is_empty_200() {
        let resp = call(r#"[{"pattern": "^/v1/ok$"}]"#, "GET", "/v1/ok").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert!(bytes.is_empty());
    }

    #[test]
    fn invalid_rules_fail_compilation() {
        let bad = rules(r#"[{"pattern": "("}]"#);
        assert!(MockResponseLayer::from_config(&bad, "api").is_err());
    }
}
