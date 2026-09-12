//! [`ProxyBody`]: the canonical body type flowing through a middleware chain.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;

use crate::BoxError;

/// The canonical body type flowing through a middleware chain: either a
/// locally generated body (errors, health checks) or a streamed client or
/// upstream body, boxed at the chain boundary.
///
/// Deliberately a concrete struct rather than a `BoxBody` type alias: a
/// naked `dyn` trait-object lifetime inside a tower service's request and
/// response types makes rustc reject driving the service inside a `Send`
/// future with "implementation of `tower::Service` is not general enough"
/// (rust-lang/rust#102211). Wrapping the boxing in a lifetime-parameter-free
/// struct — the same approach as axum's `Body` — leaves nothing to
/// generalize.
pub struct ProxyBody(BoxBody<Bytes, BoxError>);

impl ProxyBody {
    /// Boxes `body`, erasing its concrete type.
    pub fn new<B>(body: B) -> Self
    where
        B: Body<Data = Bytes> + Send + Sync + 'static,
        B::Error: Into<BoxError>,
    {
        Self(body.map_err(Into::into).boxed())
    }

    /// An empty body.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(http_body_util::Empty::new())
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().0).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

impl std::fmt::Debug for ProxyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyBody").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::Full;

    use super::*;

    #[tokio::test]
    async fn boxes_and_streams_a_body() {
        let body = ProxyBody::new(Full::new(Bytes::from_static(b"payload")));
        let collected = body.collect().await.expect("collect").to_bytes();
        assert_eq!(&collected[..], b"payload");
    }

    #[tokio::test]
    async fn empty_body_is_empty() {
        let body = ProxyBody::empty();
        assert!(body.is_end_stream());
        let collected = body.collect().await.expect("collect").to_bytes();
        assert!(collected.is_empty());
    }
}
