//! The HTTP seam for Universal Data Graph data-source fetches (ADR-0010).
//!
//! UDG execution (`graphql_udg`) calls REST and GraphQL upstreams
//! mid-request, but g2-middleware carries no HTTP client or TLS stack: the
//! actual request is abstracted behind [`UdgFetch`], implemented by the
//! proxy crate over its shared upstream client (the
//! [`JwksFetch`](crate::JwksFetch) inversion). Tests substitute in-memory
//! fakes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::{Method, StatusCode};

/// One data-source fetch: everything the executor renders per request.
#[derive(Debug)]
pub struct UdgRequest {
    /// HTTP method of the fetch.
    pub method: Method,
    /// Absolute `http(s)` URL (already rendered and shape-checked).
    pub url: String,
    /// Headers to set on the fetch (already rendered and parsed).
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Request body, if the source configures one.
    pub body: Option<bytes::Bytes>,
    /// Per-fetch timeout; expiry is a fetch error.
    pub timeout: Duration,
    /// Cap on the response body; exceeding it is a fetch error.
    pub max_response_bytes: usize,
}

/// A completed data-source fetch. Non-2xx statuses are returned, not
/// treated as errors — the executor decides what they mean.
#[derive(Debug)]
pub struct UdgResponse {
    /// The upstream's response status.
    pub status: StatusCode,
    /// The response body, capped at
    /// [`max_response_bytes`](UdgRequest::max_response_bytes).
    pub body: bytes::Bytes,
}

/// Boxed future returned by [`UdgFetch::fetch`].
pub type UdgFetchFuture =
    Pin<Box<dyn Future<Output = Result<UdgResponse, String>> + Send + 'static>>;

/// Performs one UDG data-source HTTP request.
///
/// Implemented by the proxy crate over its shared upstream HTTPS client.
/// Errors are plain strings; the executor maps them to GraphQL field
/// errors without exposing upstream detail to clients.
pub trait UdgFetch: Send + Sync + 'static {
    /// Sends `request` and returns the status plus the capped body.
    fn fetch(&self, request: UdgRequest) -> UdgFetchFuture;
}

/// Shared fetcher handle threaded into
/// [`GraphQlLayer::from_config`](crate::GraphQlLayer::from_config).
pub type SharedUdgFetch = Arc<dyn UdgFetch>;
