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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use g2_core::{ApiDefinition, Error};
use g2_middleware::{ClientAddr, ProxyBody};
use http::uri::{Authority, Scheme, Uri};
use http::{Method, Request, Response, StatusCode, Version};
use hyper_rustls::{ConfigBuilderExt as _, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tower::Service;

/// The pooled upstream client: TLS-capable, with plain `http://` requests
/// bypassing TLS inside the connector (`https_or_http`).
type UpstreamClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

use crate::response::error_response;
use crate::rewrite;

/// The precomputed parts of one upstream base URL: where a request is sent
/// once an address has been picked from the target's rotation.
#[derive(Debug, Clone)]
pub struct UpstreamAddr {
    /// Upstream scheme parsed from the target URL.
    pub scheme: Scheme,
    /// Upstream `host[:port]` parsed from the target URL.
    pub authority: Authority,
    /// Upstream base path from the target URL, trailing-slash-trimmed
    /// (`""` when the URL has no path).
    pub base_path: String,
}

impl UpstreamAddr {
    /// Precomputes the parts of one target URL.
    ///
    /// # Panics
    ///
    /// Panics if `url` has not passed [`ApiDefinition::validate`]'s target
    /// URL checks; callers must validate the definition first.
    fn from_url(url: &str) -> Self {
        let uri: Uri = url.parse().expect("target URL validated as a URI");
        Self {
            scheme: uri.scheme().expect("validated scheme").clone(),
            authority: uri.authority().expect("validated authority").clone(),
            base_path: uri.path().trim_end_matches('/').to_owned(),
        }
    }
}

/// Everything about an API's upstream precomputed at route-build time so
/// forwarding does no per-request parsing.
#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    /// The `api_id` of the API definition (for logs and error context).
    pub api_id: String,
    /// `listen_path` with any trailing `/` removed (`"/users"`; empty for `"/"`).
    pub listen_prefix: String,
    /// The upstream addresses requests are forwarded to. Never empty: the
    /// definition's `target_list` when configured, else its single
    /// `target_url`.
    pub targets: Vec<UpstreamAddr>,
    /// Whether the listen-path prefix is removed before forwarding.
    pub strip_listen_path: bool,
    /// Whether the client's `Host` header is forwarded unchanged.
    pub preserve_host_header: bool,
    /// Per-API upstream timeout.
    pub timeout: Duration,
    /// URL rewrite rules with precompiled patterns, tried in order.
    pub(crate) rewrites: Vec<rewrite::CompiledRewrite>,
    /// Method override applied to the upstream-bound request.
    pub(crate) method_override: Option<Method>,
    /// Round-robin cursor over `targets`, shared across clones so every
    /// handle to this target advances one rotation.
    next_target: Arc<AtomicUsize>,
}

impl UpstreamTarget {
    /// Validates `def` and precomputes its upstream target parts.
    pub(crate) fn build(def: &ApiDefinition) -> Result<Self, Error> {
        def.validate()?;
        let targets = if def.target_list.is_empty() {
            vec![UpstreamAddr::from_url(&def.target_url)]
        } else {
            def.target_list
                .iter()
                .map(|url| UpstreamAddr::from_url(url))
                .collect()
        };
        let rewrites = def
            .url_rewrites
            .iter()
            .map(|rule| rewrite::CompiledRewrite::compile(rule, &def.api_id))
            .collect::<Result<Vec<_>, _>>()?;
        let method_override = def
            .transform_method
            .as_deref()
            .map(|m| {
                Method::from_bytes(m.to_ascii_uppercase().as_bytes()).map_err(|_| {
                    Error::InvalidApiDefinition {
                        api: def.api_id.clone(),
                        reason: format!("`transform_method` is not a valid method: `{m}`"),
                    }
                })
            })
            .transpose()?;
        Ok(Self {
            api_id: def.api_id.clone(),
            listen_prefix: def.listen_path.trim_end_matches('/').to_owned(),
            targets,
            strip_listen_path: def.strip_listen_path,
            preserve_host_header: def.preserve_host_header,
            timeout: Duration::from_millis(def.upstream_timeout_ms),
            rewrites,
            method_override,
            next_target: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// The upstream address the next request should use: round-robin across
    /// [`Self::targets`], pod-local (no cross-pod coordination — each
    /// gateway process keeps its own rotation).
    ///
    /// Single-target APIs skip the atomic entirely, so unbalanced routes pay
    /// nothing for this feature. The cursor wraps at `usize::MAX`, which can
    /// skip ahead in the rotation once per ~2^64 requests — harmless.
    #[must_use]
    pub fn next_addr(&self) -> &UpstreamAddr {
        if self.targets.len() == 1 {
            return &self.targets[0];
        }
        let index = self.next_target.fetch_add(1, Ordering::Relaxed) % self.targets.len();
        &self.targets[index]
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
    client: UpstreamClient,
}

impl Forwarder {
    /// Creates a forwarder with a default pooled client.
    ///
    /// `https://` upstreams are verified against the platform CA store; when
    /// no usable platform store exists (some containers), the embedded
    /// webpki (Mozilla) roots are used instead. To trust a private CA, build
    /// the forwarder with [`Forwarder::with_tls_config`].
    #[must_use]
    pub fn new() -> Self {
        let tls = match rustls::ClientConfig::builder().with_native_roots() {
            Ok(builder) => builder.with_no_client_auth(),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "no usable platform CA store; https upstreams verify against embedded webpki roots"
                );
                rustls::ClientConfig::builder()
                    .with_webpki_roots()
                    .with_no_client_auth()
            }
        };
        Self::with_tls_config(tls)
    }

    /// Creates a forwarder whose `https://` upstream connections use the
    /// given rustls configuration (custom CA roots, for instance).
    #[must_use]
    pub fn with_tls_config(tls: rustls::ClientConfig) -> Self {
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
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
    client: UpstreamClient,
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
    client: &UpstreamClient,
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

    let addr = target.next_addr();
    let (mut parts, body) = req.into_parts();
    let path_and_query =
        rewrite::upstream_path_and_query(target, addr, parts.uri.path(), parts.uri.query());
    let upstream_uri = Uri::builder()
        .scheme(addr.scheme.clone())
        .authority(addr.authority.clone())
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
    if let Some(method) = &target.method_override {
        parts.method = method.clone();
    }
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
        // A request body that blew its API's size limit fails the upstream
        // send from the inside; surface that as 413, not a bogus 502.
        Ok(Err(err)) if g2_middleware::is_request_too_large(&err) => {
            tracing::debug!(%api_id, "request body exceeded the API's size limit mid-stream");
            error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
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
    use std::net::{Ipv4Addr, SocketAddr};

    use http_body_util::BodyExt;
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use super::*;

    /// Serves `"tls ok"` over HTTPS with a fresh self-signed `localhost`
    /// cert; returns the bound address and a root store trusting that cert.
    async fn spawn_tls_upstream() -> (SocketAddr, rustls::RootCertStore) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("self-signed cert");
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).expect("trust anchor");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return; // e.g. a client that rejects our cert
                    };
                    let service = hyper::service::service_fn(|_req| async {
                        Ok::<_, Infallible>(Response::new(http_body_util::Full::new(
                            bytes::Bytes::from_static(b"tls ok"),
                        )))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        (addr, roots)
    }

    fn tls_target(addr: SocketAddr) -> Arc<UpstreamTarget> {
        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"tls","name":"tls","listen_path":"/tls/","target_url":"https://localhost:{}"}}"#,
            addr.port()
        ))
        .expect("def");
        Arc::new(UpstreamTarget::build(&def).expect("target"))
    }

    #[tokio::test]
    async fn https_upstream_with_trusted_root_proxies() {
        let (addr, roots) = spawn_tls_upstream().await;
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let svc = Forward::new(&Forwarder::with_tls_config(tls), tls_target(addr));

        let req = Request::builder()
            .uri("/tls/x")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(&body[..], b"tls ok");
    }

    #[tokio::test]
    async fn https_upstream_with_untrusted_cert_maps_to_502() {
        let (addr, _roots) = spawn_tls_upstream().await;
        // The default forwarder trusts only real CA roots, so the
        // self-signed upstream must fail verification, not proxy.
        let svc = Forward::new(&Forwarder::new(), tls_target(addr));

        let req = Request::builder()
            .uri("/tls/x")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn round_robin_rotates_and_shares_across_clones() {
        let def: ApiDefinition = serde_json::from_str(
            r#"{"api_id":"lb","name":"lb","listen_path":"/lb/",
                "target_url":"http://unused.internal",
                "target_list":["http://a.internal","http://b.internal","http://c.internal"]}"#,
        )
        .expect("def");
        let target = UpstreamTarget::build(&def).expect("target");

        let hosts: Vec<&str> = (0..4)
            .map(|_| target.next_addr().authority.host())
            .collect();
        assert_eq!(
            hosts,
            ["a.internal", "b.internal", "c.internal", "a.internal"]
        );

        // Clones share the cursor: the rotation continues, never restarts.
        let clone = target.clone();
        assert_eq!(clone.next_addr().authority.host(), "b.internal");
        assert_eq!(target.next_addr().authority.host(), "c.internal");
    }

    #[test]
    fn single_target_comes_from_target_url() {
        let def: ApiDefinition = serde_json::from_str(
            r#"{"api_id":"one","name":"one","listen_path":"/one/",
                "target_url":"http://only.internal:8080/base"}"#,
        )
        .expect("def");
        let target = UpstreamTarget::build(&def).expect("target");
        assert_eq!(target.targets.len(), 1);
        for _ in 0..3 {
            assert_eq!(target.next_addr().authority.as_str(), "only.internal:8080");
        }
    }

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
