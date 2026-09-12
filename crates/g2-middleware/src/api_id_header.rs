//! [`ApiIdHeaderLayer`]: stamps the matched API's id onto the upstream-bound
//! request as [`API_ID_HEADER`].

use http::header::HeaderName;
use http::{HeaderValue, Request};
use tower::{Layer, Service};

use crate::context::RequestContext;

/// Header carrying the matched API's id to the upstream.
pub const API_ID_HEADER: HeaderName = HeaderName::from_static("x-g2-api-id");

/// Layer that sets [`API_ID_HEADER`] from the [`RequestContext`] extension.
///
/// The header is `insert`ed (replacing any existing value) — and removed
/// entirely when no context is present or the id is not a valid header value —
/// so a client-supplied `x-g2-api-id` can never reach the upstream.
#[derive(Debug, Clone, Default)]
pub struct ApiIdHeaderLayer;

impl ApiIdHeaderLayer {
    /// Creates the layer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for ApiIdHeaderLayer {
    type Service = ApiIdHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ApiIdHeader { inner }
    }
}

/// The service produced by [`ApiIdHeaderLayer`].
#[derive(Debug, Clone)]
pub struct ApiIdHeader<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for ApiIdHeader<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let value = req
            .extensions()
            .get::<RequestContext>()
            .and_then(|ctx| HeaderValue::from_str(ctx.api_id()).ok());
        match value {
            Some(v) => {
                req.headers_mut().insert(API_ID_HEADER, v);
            }
            None => {
                req.headers_mut().remove(API_ID_HEADER);
            }
        }
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use tower::ServiceExt;

    use super::*;

    /// Inner service echoing the header value it received.
    fn recorder(
    ) -> impl Service<Request<()>, Response = Option<HeaderValue>, Error = Infallible> + Clone {
        tower::service_fn(|req: Request<()>| async move {
            Ok::<_, Infallible>(req.headers().get(API_ID_HEADER).cloned())
        })
    }

    #[tokio::test]
    async fn stamps_api_id_from_context() {
        let svc = ApiIdHeaderLayer::new().layer(recorder());
        let mut req = Request::new(());
        req.extensions_mut()
            .insert(RequestContext::new("users-api", "acme"));

        let header = svc.oneshot(req).await.expect("infallible");
        assert_eq!(header.expect("header set").as_bytes(), b"users-api");
    }

    #[tokio::test]
    async fn overwrites_client_supplied_value() {
        let svc = ApiIdHeaderLayer::new().layer(recorder());
        let mut req = Request::new(());
        req.headers_mut()
            .insert(API_ID_HEADER, HeaderValue::from_static("spoofed"));
        req.extensions_mut()
            .insert(RequestContext::new("real-api", "acme"));

        let header = svc.oneshot(req).await.expect("infallible");
        assert_eq!(header.expect("header set").as_bytes(), b"real-api");
    }

    #[tokio::test]
    async fn removes_header_without_context() {
        let svc = ApiIdHeaderLayer::new().layer(recorder());
        let mut req = Request::new(());
        req.headers_mut()
            .insert(API_ID_HEADER, HeaderValue::from_static("spoofed"));

        let header = svc.oneshot(req).await.expect("infallible");
        assert!(header.is_none(), "spoofed header must not pass through");
    }
}
