//! Upstream forwarding: the innermost service of every middleware chain.
//!
//! [`Forwarder`] is the process-wide handle to the pooled upstream HTTP
//! client; the private `Forward` type is the per-route tower service that
//! rewrites a request for its [`UpstreamTarget`] and proxies it, enforcing
//! the per-API timeout.

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use g2_core::{ApiDefinition, Error};
use g2_middleware::{ClientAddr, ProxyBody};
use http::uri::{Authority, Scheme, Uri};
use http::{Request, Response, StatusCode, Version};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tower::Service;

use crate::response::error_response;
use crate::rewrite;

/// Everything about an API's upstream precomputed at route-build time so
/// forwarding does no per-request parsing.
#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    /// The `api_id` of the API definition (for logs and error context).
    pub api_id: String,
    /// `listen_path` with any trailing `/` removed (`"/users"`; empty for `"/"`).
    pub listen_prefix: String,
    /// Upstream scheme parsed from `target_url`.
    pub scheme: Scheme,
    /// Upstream `host[:port]` parsed from `target_url`.
    pub authority: Authority,
    /// Upstream base path from `target_url` (`""` when the URL has no path).
    pub base_path: String,
    /// Whether the listen-path prefix is removed before forwarding.
    pub strip_listen_path: bool,
    /// Whether the client's `Host` header is forwarded unchanged.
    pub preserve_host_header: bool,
    /// Per-API upstream timeout.
    pub timeout: Duration,
}

impl UpstreamTarget {
    /// Validates `def` and precomputes its upstream target parts.
    pub(crate) fn build(def: &ApiDefinition) -> Result<Self, Error> {
        def.validate()?;
        let target = def.target_uri();
        let scheme = target.scheme().expect("validated scheme").clone();
        let authority = target.authority().expect("validated authority").clone();
        Ok(Self {
            api_id: def.api_id.clone(),
            listen_prefix: def.listen_path.trim_end_matches('/').to_owned(),
            scheme,
            authority,
            base_path: target.path().trim_end_matches('/').to_owned(),
            strip_listen_path: def.strip_listen_path,
            preserve_host_header: def.preserve_host_header,
            timeout: Duration::from_millis(def.upstream_timeout_ms),
        })
    }
}

/// Process-wide handle to the pooled upstream HTTP client.
///
/// Cheap to clone — clones share one connection pool — so a single
/// `Forwarder` created at startup is passed to every
/// [`RouteTable::build`](crate::RouteTable::build), and upstream connections
/// survive config hot reloads.
#[derive(Debug, Clone)]
pub struct Forwarder {
    client: Client<HttpConnector, ProxyBody>,
}

impl Forwarder {
    /// Creates a forwarder with a default pooled HTTP client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
        }
    }
}

impl Default for Forwarder {
    fn default() -> Self {
        Self::new()
    }
}

/// The innermost chain service of one route: rewrites the request for the
/// route's upstream and proxies it.
///
/// Failures never surface as service errors — an unreachable upstream maps to
/// `502` and a timeout to `504` — keeping the chain's `Infallible` contract.
#[derive(Debug, Clone)]
pub(crate) struct Forward {
    client: Client<HttpConnector, ProxyBody>,
    target: Arc<UpstreamTarget>,
}

impl Forward {
    /// Creates the forwarding service for `target` using `forwarder`'s client.
    pub(crate) fn new(forwarder: &Forwarder, target: Arc<UpstreamTarget>) -> Self {
        Self {
            client: forwarder.client.clone(),
            target,
        }
    }
}

impl Service<Request<ProxyBody>> for Forward {
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<ProxyBody>, Infallible>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<ProxyBody>) -> Self::Future {
        let client = self.client.clone();
        let target = Arc::clone(&self.target);
        Box::pin(async move { Ok(forward(&client, &target, req).await) })
    }
}

/// Forwards one rewritten request to the upstream of `target`.
async fn forward(
    client: &Client<HttpConnector, ProxyBody>,
    target: &UpstreamTarget,
    req: Request<ProxyBody>,
) -> Response<ProxyBody> {
    let api_id = target.api_id.as_str();
    // The gateway records the peer address before the chain runs; the
    // unspecified address is a defensive fallback for callers that did not
    // (it renders as `0.0.0.0` in `X-Forwarded-For`).
    let client_ip = req
        .extensions()
        .get::<ClientAddr>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |addr| addr.0.ip());

    let (mut parts, body) = req.into_parts();
    let path_and_query =
        rewrite::upstream_path_and_query(target, parts.uri.path(), parts.uri.query());
    let upstream_uri = Uri::builder()
        .scheme(target.scheme.clone())
        .authority(target.authority.clone())
        .path_and_query(path_and_query)
        .build();
    let upstream_uri = match upstream_uri {
        Ok(uri) => uri,
        Err(err) => {
            tracing::error!(%api_id, error = %err, "failed to build upstream URI");
            return error_response(StatusCode::BAD_GATEWAY, "invalid upstream request");
        }
    };
    parts.uri = upstream_uri;
    // The upstream connection is negotiated by the client independently
    // of the client-facing protocol version.
    parts.version = Version::HTTP_11;
    rewrite::prepare_upstream_headers(&mut parts.headers, target, client_ip);
    let upstream_req = Request::from_parts(parts, body);

    tracing::debug!(%api_id, uri = %upstream_req.uri(), "forwarding upstream");
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(target.timeout, client.request(upstream_req)).await;
    // Time spent talking to the upstream (to failure/timeout on the error
    // paths), recorded on the request span (a no-op without a TraceLayer).
    let upstream_elapsed = started.elapsed();
    tracing::Span::current().record(
        g2_middleware::trace::UPSTREAM_LATENCY_FIELD,
        u64::try_from(upstream_elapsed.as_millis()).unwrap_or(u64::MAX),
    );
    let mut resp = match outcome {
        Ok(Ok(mut resp)) => {
            rewrite::strip_hop_by_hop_headers(resp.headers_mut());
            resp.map(ProxyBody::new)
        }
        Ok(Err(err)) => {
            tracing::warn!(%api_id, error = %err, "upstream request failed");
            error_response(StatusCode::BAD_GATEWAY, "upstream request failed")
        }
        Err(_elapsed) => {
            tracing::warn!(%api_id, timeout_ms = target.timeout.as_millis(), "upstream timed out");
            error_response(StatusCode::GATEWAY_TIMEOUT, "upstream request timed out")
        }
    };
    // Stamped on every outcome (502/504 included) so outer layers can
    // attribute latency to the upstream leg.
    resp.extensions_mut()
        .insert(g2_middleware::UpstreamLatency(upstream_elapsed));
    resp
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn unreachable_upstream_maps_to_502_not_error() {
        // Bind-then-drop a listener to obtain a port with nothing behind it.
        let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = dead.local_addr().expect("addr");
        drop(dead);

        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"down","name":"down","listen_path":"/down/","target_url":"http://{addr}"}}"#
        ))
        .expect("def");
        let target = Arc::new(UpstreamTarget::build(&def).expect("target"));
        let svc = Forward::new(&Forwarder::new(), target);

        let req = Request::builder()
            .uri("/down/x")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
