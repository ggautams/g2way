//! [`PathPolicyLayer`]: per-API allow/block/ignore path lists.
//!
//! Sits directly below [`SetContextLayer`](crate::SetContextLayer) and
//! **above** auth, so a blocked path is rejected before any credential work
//! and an ignored path can tell the auth layer to stand down (via the
//! [`AuthBypass`] request extension).
//!
//! Evaluation order (deliberately strict — an ignored path does **not**
//! bypass the block list; see `g2_core::endpoints`):
//!
//! 1. **Block**: a request matching `block_paths` is rejected with `403`,
//!    unconditionally.
//! 2. **Allow**: when `allow_paths` is non-empty, a request matching none
//!    of its rules is rejected with `403`. Blocked and not-allowed share
//!    one message, so callers cannot probe which list produced a rejection.
//! 3. **Ignore**: a request matching `ignore_auth_paths` is stamped with
//!    [`AuthBypass`] and forwarded without authentication (and therefore
//!    without session rate limiting, which needs a session — API-level
//!    endpoint rate limits still apply, they count aggregate traffic).
//!
//! Patterns are compiled once at route-build time; the hot path only runs
//! prebuilt automata (the `regex` crate is linear-time, so hostile paths
//! cannot ReDoS the gateway).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use g2_core::{Error, PathRule};
use http::{Method, Request, Response, StatusCode};
use regex::Regex;
use tower::{Layer, Service};

use crate::context::AuthBypass;
use crate::response::json_error;
use crate::ProxyBody;

/// One 403 message for both blocked and not-allow-listed paths; which list
/// rejected a request must not leak to the caller.
const FORBIDDEN_PATH_MSG: &str = "requested endpoint is forbidden";

/// One compiled path rule: prebuilt regex plus an optional method filter.
#[derive(Debug)]
struct CompiledRule {
    regex: Regex,
    /// Methods the rule applies to; empty = every method.
    methods: Vec<Method>,
}

impl CompiledRule {
    fn compile(rule: &PathRule, api_id: &str) -> Result<Self, Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api_id.to_owned(),
            reason,
        };
        let regex = Regex::new(&rule.pattern)
            .map_err(|e| fail(format!("invalid path rule regex `{}`: {e}", rule.pattern)))?;
        let methods = rule
            .methods
            .iter()
            .map(|m| {
                Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                    .map_err(|_| fail(format!("invalid path rule method `{m}`")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { regex, methods })
    }

    fn matches(&self, method: &Method, path: &str) -> bool {
        (self.methods.is_empty() || self.methods.contains(method)) && self.regex.is_match(path)
    }
}

fn compile_list(rules: &[PathRule], api_id: &str) -> Result<Vec<CompiledRule>, Error> {
    rules
        .iter()
        .map(|r| CompiledRule::compile(r, api_id))
        .collect()
}

fn any_match(rules: &[CompiledRule], method: &Method, path: &str) -> bool {
    rules.iter().any(|r| r.matches(method, path))
}

/// One API's compiled path lists, shared by every clone of the service.
#[derive(Debug)]
struct PolicyState {
    allow: Vec<CompiledRule>,
    block: Vec<CompiledRule>,
    ignore: Vec<CompiledRule>,
}

/// Tower layer enforcing one API's allow/block/ignore path lists.
#[derive(Debug, Clone)]
pub struct PathPolicyLayer {
    state: Arc<PolicyState>,
}

impl PathPolicyLayer {
    /// Compiles the three lists into a layer, or `None` when all are empty
    /// (the API gets no policy layer at all); `api_id` names the API in
    /// errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a pattern or method
    /// does not compile. Definitions are validated before routes are built,
    /// so this failing indicates a validation gap, but the route build
    /// surfaces it loudly rather than panicking.
    pub fn from_config(
        allow: &[PathRule],
        block: &[PathRule],
        ignore: &[PathRule],
        api_id: &str,
    ) -> Result<Option<Self>, Error> {
        if allow.is_empty() && block.is_empty() && ignore.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            state: Arc::new(PolicyState {
                allow: compile_list(allow, api_id)?,
                block: compile_list(block, api_id)?,
                ignore: compile_list(ignore, api_id)?,
            }),
        }))
    }
}

impl<S> Layer<S> for PathPolicyLayer {
    type Service = PathPolicy<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PathPolicy {
            inner,
            state: Arc::clone(&self.state),
        }
    }
}

/// The [`Service`] produced by [`PathPolicyLayer`].
#[derive(Debug, Clone)]
pub struct PathPolicy<S> {
    inner: S,
    state: Arc<PolicyState>,
}

impl<S> Service<Request<ProxyBody>> for PathPolicy<S>
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

    fn call(&mut self, mut req: Request<ProxyBody>) -> Self::Future {
        let method = req.method().clone();
        let path = req.uri().path();

        if any_match(&self.state.block, &method, path)
            || (!self.state.allow.is_empty() && !any_match(&self.state.allow, &method, path))
        {
            return Box::pin(std::future::ready(Ok(json_error(
                StatusCode::FORBIDDEN,
                FORBIDDEN_PATH_MSG,
            ))));
        }
        if any_match(&self.state.ignore, &method, path) {
            req.extensions_mut().insert(AuthBypass);
        }
        Box::pin(self.inner.call(req))
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

    fn rules(json: &str) -> Vec<PathRule> {
        serde_json::from_str(json).expect("valid rules JSON")
    }

    /// Inner service reporting whether the bypass marker arrived.
    async fn echo_bypass(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let mut resp = Response::new(body());
        if req.extensions().get::<AuthBypass>().is_some() {
            resp.headers_mut()
                .insert("x-echo-bypass", http::HeaderValue::from_static("1"));
        }
        Ok(resp)
    }

    fn layer(allow: &str, block: &str, ignore: &str) -> PathPolicyLayer {
        PathPolicyLayer::from_config(&rules(allow), &rules(block), &rules(ignore), "api")
            .expect("compiles")
            .expect("non-empty config")
    }

    async fn call(layer: &PathPolicyLayer, method: &str, path: &str) -> Response<ProxyBody> {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(body())
            .expect("request");
        layer
            .layer(tower::service_fn(echo_bypass))
            .oneshot(req)
            .await
            .expect("infallible")
    }

    #[test]
    fn empty_config_builds_no_layer() {
        assert!(PathPolicyLayer::from_config(&[], &[], &[], "api")
            .expect("ok")
            .is_none());
    }

    #[tokio::test]
    async fn block_list_rejects_matching_paths_and_methods() {
        let layer = layer(
            "[]",
            r#"[{"pattern": "^/v1/admin", "methods": ["POST"]}]"#,
            "[]",
        );
        assert_eq!(
            call(&layer, "POST", "/v1/admin/x").await.status(),
            StatusCode::FORBIDDEN
        );
        // Other method / other path pass.
        assert_eq!(
            call(&layer, "GET", "/v1/admin/x").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            call(&layer, "POST", "/v1/other").await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn allow_list_makes_the_api_allow_list_only() {
        let layer = layer(r#"[{"pattern": "^/v1/public/"}]"#, "[]", "[]");
        assert_eq!(
            call(&layer, "GET", "/v1/public/x").await.status(),
            StatusCode::OK
        );
        let resp = call(&layer, "GET", "/v1/private").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn block_wins_over_allow_and_ignore() {
        let layer = layer(
            r#"[{"pattern": "^/v1/"}]"#,
            r#"[{"pattern": "^/v1/blocked$"}]"#,
            r#"[{"pattern": "^/v1/blocked$"}]"#,
        );
        assert_eq!(
            call(&layer, "GET", "/v1/blocked").await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&layer, "GET", "/v1/fine").await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn ignore_match_stamps_auth_bypass() {
        let layer = layer("[]", "[]", r#"[{"pattern": "^/v1/ping$"}]"#);
        let resp = call(&layer, "GET", "/v1/ping").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("x-echo-bypass"));

        let resp = call(&layer, "GET", "/v1/other").await;
        assert!(!resp.headers().contains_key("x-echo-bypass"));
    }

    #[tokio::test]
    async fn ignored_paths_must_still_be_allow_listed() {
        // Ignore skips auth, not the allow list.
        let layer = layer(
            r#"[{"pattern": "^/v1/public/"}]"#,
            "[]",
            r#"[{"pattern": "^/v1/ping$"}]"#,
        );
        assert_eq!(
            call(&layer, "GET", "/v1/ping").await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn invalid_rules_fail_compilation() {
        let bad = vec![PathRule {
            pattern: "(".into(),
            methods: vec![],
        }];
        assert!(PathPolicyLayer::from_config(&bad, &[], &[], "api").is_err());
    }
}
