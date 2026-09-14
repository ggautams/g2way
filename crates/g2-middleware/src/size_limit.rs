//! [`RequestSizeLimitLayer`]: per-API request body size limits.
//!
//! Sits above auth (an oversized request is rejected before any credential
//! work) and below the path policy. Enforcement is two-tier:
//!
//! 1. A declared `Content-Length` above the limit is rejected immediately
//!    with `413` — the cheap path, and the only one most requests hit.
//! 2. The body is wrapped in a counting reader that fails with
//!    [`RequestTooLarge`] once more bytes than the limit actually arrive —
//!    covering chunked and HTTP/2 streams that declare no length. The
//!    error aborts the upstream forward mid-stream; the forwarder
//!    recognizes it and maps that failure to `413` too.
//!
//! The wrapper costs one boxing per request on APIs with a limit
//! configured; it cannot be precomputed because it carries per-request
//! state (the running byte count).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{header, Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use tower::{Layer, Service};

use crate::response::json_error;
use crate::{BoxError, ProxyBody};

/// Client-facing message for both rejection tiers.
const TOO_LARGE_MSG: &str = "request body too large";

/// Error a limited request body fails with once it exceeds its API's
/// `max_request_body_bytes`.
///
/// It surfaces inside the upstream client's error chain; the forwarder
/// downcasts for it to answer `413` instead of a generic `502`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestTooLarge {
    /// The configured limit that was exceeded, in bytes.
    pub limit: u64,
}

impl std::fmt::Display for RequestTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request body exceeded the {}-byte limit", self.limit)
    }
}

impl std::error::Error for RequestTooLarge {}

/// Whether any error in `err`'s source chain is a [`RequestTooLarge`].
#[must_use]
pub fn is_request_too_large(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(err) = current {
        if err.is::<RequestTooLarge>() {
            return true;
        }
        current = err.source();
    }
    false
}

/// Whether `err`'s source chain carries either over-limit marker: this
/// layer's mid-stream [`RequestTooLarge`] or a buffering layer's
/// [`http_body_util::LengthLimitError`] (from `Limited`). Body-buffering
/// layers use this to answer `413`/`502` for oversized payloads instead of
/// mistaking them for transport errors.
pub(crate) fn is_over_limit(err: &(dyn std::error::Error + 'static)) -> bool {
    if is_request_too_large(err) {
        return true;
    }
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(err) = current {
        if err.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        current = err.source();
    }
    false
}

/// A request body that fails with [`RequestTooLarge`] once more than
/// `remaining` bytes have been produced.
struct LimitedBody {
    inner: ProxyBody,
    limit: u64,
    remaining: u64,
}

impl Body for LimitedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.len() as u64;
                    if len > this.remaining {
                        this.remaining = 0;
                        return Poll::Ready(Some(Err(Box::new(RequestTooLarge {
                            limit: this.limit,
                        }))));
                    }
                    this.remaining -= len;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

/// Tower layer enforcing one API's request body size limit.
#[derive(Debug, Clone)]
pub struct RequestSizeLimitLayer {
    limit: u64,
}

impl RequestSizeLimitLayer {
    /// Creates a layer rejecting request bodies larger than `limit` bytes.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self { limit }
    }
}

impl<S> Layer<S> for RequestSizeLimitLayer {
    type Service = RequestSizeLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestSizeLimit {
            inner,
            limit: self.limit,
        }
    }
}

/// The [`Service`] produced by [`RequestSizeLimitLayer`].
#[derive(Debug, Clone)]
pub struct RequestSizeLimit<S> {
    inner: S,
    limit: u64,
}

impl<S> Service<Request<ProxyBody>> for RequestSizeLimit<S>
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
        // Tier 1: a declared length over the limit is rejected up front.
        // (hyper enforces that a body never exceeds its declared length,
        // so an under-declared Content-Length cannot smuggle extra bytes.)
        let declared = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|len| len > self.limit) {
            return Box::pin(std::future::ready(Ok(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                TOO_LARGE_MSG,
            ))));
        }

        // Tier 2: count what actually arrives (chunked / h2 streams).
        let limit = self.limit;
        let req = req.map(|inner| {
            ProxyBody::new(LimitedBody {
                inner,
                limit,
                remaining: limit,
            })
        });
        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::{BodyExt, Full, StreamBody};
    use tower::ServiceExt;

    use super::*;

    /// Inner service that drains the request body, surfacing body errors as
    /// a 500 with the error text (mimicking how the forwarder sees them).
    async fn draining(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        match req.into_body().collect().await {
            Ok(collected) => {
                let len = collected.to_bytes().len().to_string();
                let mut resp = Response::new(ProxyBody::empty());
                resp.headers_mut()
                    .insert("x-body-len", len.parse().expect("len value"));
                Ok(resp)
            }
            Err(err) => {
                let status = if is_request_too_large(err.as_ref()) {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                Ok(json_error(status, &err.to_string()))
            }
        }
    }

    async fn send(limit: u64, req: Request<ProxyBody>) -> Response<ProxyBody> {
        RequestSizeLimitLayer::new(limit)
            .layer(tower::service_fn(draining))
            .oneshot(req)
            .await
            .expect("infallible")
    }

    fn sized_request(len: usize) -> Request<ProxyBody> {
        Request::builder()
            .header(header::CONTENT_LENGTH, len.to_string())
            .body(ProxyBody::new(Full::new(Bytes::from(vec![b'x'; len]))))
            .expect("request")
    }

    /// A streaming body with no Content-Length, like a chunked upload.
    fn streaming_request(chunks: Vec<&'static [u8]>) -> Request<ProxyBody> {
        let frames = chunks
            .into_iter()
            .map(|c| Ok::<_, BoxError>(Frame::data(Bytes::from_static(c))));
        let stream = futures_util::stream::iter(frames);
        Request::builder()
            .body(ProxyBody::new(StreamBody::new(stream)))
            .expect("request")
    }

    #[tokio::test]
    async fn declared_length_over_the_limit_is_413_up_front() {
        let resp = send(10, sized_request(11)).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn bodies_within_the_limit_pass_through_intact() {
        let resp = send(10, sized_request(10)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-body-len").expect("len").as_bytes(),
            b"10"
        );
    }

    #[tokio::test]
    async fn undeclared_stream_over_the_limit_fails_mid_body() {
        let resp = send(10, streaming_request(vec![b"12345", b"12345", b"x"])).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn undeclared_stream_within_the_limit_passes() {
        let resp = send(10, streaming_request(vec![b"12345", b"12345"])).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-body-len").expect("len").as_bytes(),
            b"10"
        );
    }

    #[tokio::test]
    async fn requests_without_bodies_pass() {
        let resp = send(10, Request::new(ProxyBody::empty())).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn too_large_is_found_through_a_source_chain() {
        let leaf = RequestTooLarge { limit: 10 };
        assert!(is_request_too_large(&leaf));

        #[derive(Debug)]
        struct Wrapper(BoxError);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "wrapper")
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(self.0.as_ref())
            }
        }
        let wrapped = Wrapper(Box::new(Wrapper(Box::new(leaf))));
        assert!(is_request_too_large(&wrapped));
        assert!(!is_request_too_large(&Wrapper(Box::new(
            std::io::Error::other("io")
        ))));
    }
}
