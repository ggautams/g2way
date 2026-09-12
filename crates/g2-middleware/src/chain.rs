//! [`ChainBuilder`]: composes one API's middleware chain at route-build time.

use std::convert::Infallible;

use http::{Request, Response};
use tower::util::BoxCloneSyncService;
use tower::{Service, ServiceBuilder};

use crate::api_id_header::ApiIdHeaderLayer;
use crate::auth::AuthLayer;
use crate::context::RequestContext;
use crate::rate_limit::RateLimitLayer;
use crate::set_context::SetContextLayer;
use crate::{ChainService, ProxyBody};

/// Builds the middleware chain for one API.
///
/// Called once per route when a route table is (re)built, never on the hot
/// path. The resulting [`ChainService`] wraps the innermost forwarding
/// service with, outermost first:
///
/// 1. [`SetContextLayer`] — stamps the [`RequestContext`] extension.
/// 2. [`AuthLayer`] — token auth (absent for keyless APIs).
/// 3. [`RateLimitLayer`] — session rate/quota enforcement (absent for
///    keyless APIs, which have no session to read limits from).
/// 4. [`ApiIdHeaderLayer`] — sets `x-g2-api-id` on the upstream-bound request.
///
/// Transform layers slot in here as later M6 tasks land.
#[derive(Debug, Clone)]
pub struct ChainBuilder {
    ctx: RequestContext,
    auth: Option<AuthLayer>,
    rate_limit: Option<RateLimitLayer>,
}

impl ChainBuilder {
    /// Starts a chain for the API identified by `ctx`.
    #[must_use]
    pub fn new(ctx: RequestContext) -> Self {
        Self {
            ctx,
            auth: None,
            rate_limit: None,
        }
    }

    /// Adds token authentication (`None` — from a keyless config — is a
    /// no-op, keeping the call site branch-free).
    #[must_use]
    pub fn auth(mut self, auth: Option<AuthLayer>) -> Self {
        self.auth = auth;
        self
    }

    /// Adds rate/quota enforcement (`None` is a no-op).
    #[must_use]
    pub fn rate_limit(mut self, rate_limit: Option<RateLimitLayer>) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// Wraps `forward` — the innermost service that actually proxies to the
    /// upstream — with this chain's layers, returning the boxed, cloneable
    /// service stored on a route.
    pub fn build<S>(self, forward: S) -> ChainService
    where
        S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let svc = ServiceBuilder::new()
            .layer(SetContextLayer::new(self.ctx))
            .option_layer(self.auth)
            .option_layer(self.rate_limit)
            .layer(ApiIdHeaderLayer::new())
            .service(forward);
        BoxCloneSyncService::new(svc)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::HeaderValue;
    use http_body_util::Full;
    use tower::ServiceExt;

    use super::*;
    use crate::API_ID_HEADER;

    fn body(text: &'static str) -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::from_static(text.as_bytes())))
    }

    /// Innermost stand-in for the forwarder: echoes the api-id header and the
    /// context extension back in response headers.
    async fn echo_forward(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let mut resp = Response::new(body("ok"));
        if let Some(v) = req.headers().get(API_ID_HEADER) {
            resp.headers_mut().insert("x-echo-api-id", v.clone());
        }
        if let Some(ctx) = req.extensions().get::<RequestContext>() {
            resp.headers_mut().insert(
                "x-echo-org-id",
                HeaderValue::from_str(ctx.org_id()).expect("test org id"),
            );
        }
        Ok(resp)
    }

    fn chain() -> ChainService {
        ChainBuilder::new(RequestContext::new("users-api", "acme"))
            .build(tower::service_fn(echo_forward))
    }

    #[tokio::test]
    async fn chain_stamps_context_and_header_end_to_end() {
        let mut req = Request::new(body(""));
        // A client-supplied value must be overwritten, not forwarded.
        req.headers_mut()
            .insert(API_ID_HEADER, HeaderValue::from_static("spoofed"));

        let resp = chain().oneshot(req).await.expect("infallible");
        assert_eq!(
            resp.headers()
                .get("x-echo-api-id")
                .expect("api id")
                .as_bytes(),
            b"users-api"
        );
        assert_eq!(
            resp.headers()
                .get("x-echo-org-id")
                .expect("org id")
                .as_bytes(),
            b"acme"
        );
    }

    #[tokio::test]
    async fn chain_clones_serve_independent_requests() {
        let chain = chain();
        for _ in 0..2 {
            let resp = chain
                .clone()
                .oneshot(Request::new(body("")))
                .await
                .expect("infallible");
            assert_eq!(
                resp.headers()
                    .get("x-echo-api-id")
                    .expect("api id")
                    .as_bytes(),
                b"users-api"
            );
        }
    }
}
