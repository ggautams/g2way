//! [`SetContextLayer`]: stamps the per-API [`RequestContext`] onto requests.

use http::Request;
use tower::{Layer, Service};

use crate::context::RequestContext;

/// Layer inserting a fixed [`RequestContext`] into every request's extensions.
///
/// Installed outermost in every chain (see
/// [`ChainBuilder`](crate::ChainBuilder)) so all downstream layers can rely on
/// the extension being present.
#[derive(Debug, Clone)]
pub struct SetContextLayer {
    ctx: RequestContext,
}

impl SetContextLayer {
    /// Creates a layer that stamps `ctx` onto every request.
    #[must_use]
    pub fn new(ctx: RequestContext) -> Self {
        Self { ctx }
    }
}

impl<S> Layer<S> for SetContextLayer {
    type Service = SetContext<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetContext {
            inner,
            ctx: self.ctx.clone(),
        }
    }
}

/// The service produced by [`SetContextLayer`].
#[derive(Debug, Clone)]
pub struct SetContext<S> {
    inner: S,
    ctx: RequestContext,
}

impl<S, B> Service<Request<B>> for SetContext<S>
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
        req.extensions_mut().insert(self.ctx.clone());
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn inserts_context_extension() {
        let svc = SetContextLayer::new(RequestContext::new("users-api", "acme")).layer(
            tower::service_fn(|req: Request<()>| async move {
                Ok::<_, Infallible>(req.extensions().get::<RequestContext>().cloned())
            }),
        );

        let ctx = svc
            .oneshot(Request::new(()))
            .await
            .expect("infallible")
            .expect("context extension present");
        assert_eq!(ctx.api_id(), "users-api");
        assert_eq!(ctx.org_id(), "acme");
    }
}
