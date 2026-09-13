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
use http_body::Body as _;
use hyper_rustls::{ConfigBuilderExt as _, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tower::Service;

/// The pooled upstream client: TLS-capable, with plain `http://` requests
/// bypassing TLS inside the connector (`https_or_http`).
pub(crate) type UpstreamClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

use crate::breaker::CircuitBreaker;
use crate::health::HealthState;
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
    /// Per-address health flags written by the checker task (see
    /// [`crate::health`]); present iff the definition enables health
    /// checking and this target forwards traffic (the base target of a
    /// versioned API does not — each version carries its own target).
    pub(crate) health: Option<Arc<HealthState>>,
    /// Per-route circuit state read and written by the forwarder (see
    /// [`crate::breaker`]); present under the same conditions as `health`.
    pub(crate) breaker: Option<Arc<CircuitBreaker>>,
    /// Additional forwarding attempts after a transport failure, for
    /// idempotent empty-body requests only.
    pub(crate) retries: u32,
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
        // The base target of a versioned API never forwards (each version's
        // effective definition — versioning stripped — builds its own
        // target), so only unversioned definitions get live health and
        // circuit state.
        let (health, breaker) = if def.versioning.is_none() {
            (
                def.health_check
                    .as_ref()
                    .map(|_| Arc::new(HealthState::new(targets.len()))),
                def.circuit_breaker
                    .as_ref()
                    .map(|cfg| Arc::new(CircuitBreaker::new(cfg, &def.api_id))),
            )
        } else {
            (None, None)
        };
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
            health,
            breaker,
            retries: def.upstream_retries,
        })
    }

    /// The upstream address the next request should use: round-robin across
    /// [`Self::targets`], pod-local (no cross-pod coordination — each
    /// gateway process keeps its own rotation). Addresses evicted
    /// by health checking are skipped — the healthy subset keeps
    /// round-robining — but eviction never empties the pool: with every
    /// address evicted, the plain rotation is used (fail open; a dead
    /// upstream then answers `502` like an unchecked one).
    ///
    /// Single-target APIs skip the atomic entirely, so unbalanced routes pay
    /// nothing for this feature. The cursor wraps at `usize::MAX`, which can
    /// skip ahead in the rotation once per ~2^64 requests — harmless.
    #[must_use]
    pub fn next_addr(&self) -> &UpstreamAddr {
        let count = self.targets.len();
        if count == 1 {
            return &self.targets[0];
        }
        for _ in 0..count {
            let index = self.next_target.fetch_add(1, Ordering::Relaxed) % count;
            if self
                .health
                .as_ref()
                .is_none_or(|health| health.is_healthy(index))
            {
                return &self.targets[index];
            }
        }
        let index = self.next_target.fetch_add(1, Ordering::Relaxed) % count;
        &self.targets[index]
    }

    /// Health of each address in [`Self::targets`], in order; `None` when
    /// health checking is not active for this target (unconfigured, or the
    /// unused base target of a versioned API). For status/dashboard APIs.
    #[must_use]
    pub fn target_health(&self) -> Option<Vec<bool>> {
        self.health.as_ref().map(|health| health.snapshot())
    }

    /// The circuit breaker's current state (`"closed"`, `"open"`,
    /// `"half_open"`); `None` when circuit breaking is not active for this
    /// target (unconfigured, or the unused base target of a versioned API).
    /// For status/dashboard APIs.
    #[must_use]
    pub fn breaker_state(&self) -> Option<&'static str> {
        self.breaker.as_ref().map(|breaker| breaker.state_name())
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

    /// The shared pooled client (health-check probes reuse it).
    pub(crate) fn client(&self) -> &UpstreamClient {
        &self.client
    }
}

impl Default for Forwarder {
    fn default() -> Self {
        Self::new()
    }
}

/// Longest a JWKS document fetch may take before it is abandoned.
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest JWKS response body accepted (real key sets are a few KB).
const MAX_JWKS_BYTES: usize = 1024 * 1024;

/// [`JwksFetch`] implementation over the shared upstream client: JWKS
/// documents are fetched through the same connection pool and TLS
/// configuration as proxied traffic and health probes.
pub(crate) struct HttpJwksFetch {
    client: UpstreamClient,
}

impl HttpJwksFetch {
    /// A fetcher borrowing `forwarder`'s pooled client.
    pub(crate) fn new(forwarder: &Forwarder) -> Self {
        Self {
            client: forwarder.client().clone(),
        }
    }
}

impl g2_middleware::JwksFetch for HttpJwksFetch {
    fn fetch(&self, url: &str) -> g2_middleware::JwksFetchFuture {
        let client = self.client.clone();
        let url = url.to_owned();
        Box::pin(async move {
            let uri: Uri = url
                .parse()
                .map_err(|e| format!("invalid JWKS URL `{url}`: {e}"))?;
            let req = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(ProxyBody::empty())
                .map_err(|e| format!("could not build JWKS request: {e}"))?;
            let resp = tokio::time::timeout(JWKS_FETCH_TIMEOUT, client.request(req))
                .await
                .map_err(|_| format!("JWKS fetch timed out after {JWKS_FETCH_TIMEOUT:?}"))?
                .map_err(|e| format!("JWKS fetch failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("JWKS endpoint answered {}", resp.status()));
            }
            let body = http_body_util::Limited::new(resp.into_body(), MAX_JWKS_BYTES);
            let collected = http_body_util::BodyExt::collect(body)
                .await
                .map_err(|e| format!("reading JWKS body failed: {e}"))?;
            Ok(collected.to_bytes())
        })
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

/// Methods that are idempotent per RFC 9110 §9.2.2 and therefore safe to
/// send again after a failed attempt.
fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

/// Why an attempt sequence ended without an upstream response.
enum AttemptError {
    /// The upstream URI could not be assembled (config/request mismatch,
    /// not upstream weather).
    BadUri,
    /// The (final) attempt failed in transport.
    Client(hyper_util::client::legacy::Error),
}

/// Runs up to `max_attempts` upstream exchanges for one request, picking a
/// fresh address from the rotation each attempt. Only transport failures are
/// retried; any upstream response — whatever its status — ends the sequence.
///
/// `body` is consumed by the last attempt; earlier attempts send an empty
/// body (the retry gate in [`forward`] only allows multiple attempts for
/// requests whose body is empty, since a streamed body cannot be replayed).
async fn run_attempts(
    client: &UpstreamClient,
    target: &UpstreamTarget,
    parts: &mut http::request::Parts,
    body: ProxyBody,
    max_attempts: u32,
) -> Result<Response<hyper::body::Incoming>, AttemptError> {
    let api_id = target.api_id.as_str();
    let mut body = Some(body);
    for attempt in 1..=max_attempts {
        let addr = target.next_addr();
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
                return Err(AttemptError::BadUri);
            }
        };
        // The last attempt takes the real body and headers; earlier ones
        // clone the headers and send an empty body. Single-attempt requests
        // (the common case) therefore never pay for a clone.
        let mut upstream_req = Request::new(if attempt == max_attempts {
            body.take().expect("consumed only by the last attempt")
        } else {
            ProxyBody::empty()
        });
        *upstream_req.method_mut() = parts.method.clone();
        *upstream_req.uri_mut() = upstream_uri;
        *upstream_req.version_mut() = parts.version;
        *upstream_req.headers_mut() = if attempt == max_attempts {
            std::mem::take(&mut parts.headers)
        } else {
            parts.headers.clone()
        };

        tracing::debug!(%api_id, uri = %upstream_req.uri(), attempt, "forwarding upstream");
        match client.request(upstream_req).await {
            Ok(resp) => return Ok(resp),
            Err(err) if attempt < max_attempts && !g2_middleware::is_request_too_large(&err) => {
                tracing::debug!(
                    %api_id,
                    error = %err,
                    attempt,
                    "upstream attempt failed; retrying against the next address"
                );
            }
            Err(err) => return Err(AttemptError::Client(err)),
        }
    }
    unreachable!("the loop returns on its last attempt")
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

    // Circuit open: shed the request without contacting the upstream. No
    // `UpstreamLatency` is stamped — there was no upstream leg.
    if let Some(breaker) = &target.breaker {
        if !breaker.try_acquire() {
            tracing::debug!(%api_id, "circuit open; rejecting without contacting the upstream");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "upstream circuit open");
        }
    }

    let (mut parts, body) = req.into_parts();
    if let Some(method) = &target.method_override {
        parts.method = method.clone();
    }
    // The upstream connection is negotiated by the client independently
    // of the client-facing protocol version.
    parts.version = Version::HTTP_11;
    rewrite::prepare_upstream_headers(&mut parts.headers, target, client_ip);
    // Retrying is safe only when the attempt can be replayed: an idempotent
    // method (after any transform) whose body is already fully drained —
    // i.e. empty. All attempts share the one per-API timeout budget below.
    let max_attempts = if target.retries > 0 && is_idempotent(&parts.method) && body.is_end_stream()
    {
        target.retries.saturating_add(1)
    } else {
        1
    };

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        target.timeout,
        run_attempts(client, target, &mut parts, body, max_attempts),
    )
    .await;
    // Time spent talking to the upstream (to failure/timeout on the error
    // paths, across all attempts), recorded on the request span (a no-op
    // without a TraceLayer).
    let upstream_elapsed = started.elapsed();
    tracing::Span::current().record(
        g2_middleware::trace::UPSTREAM_LATENCY_FIELD,
        u64::try_from(upstream_elapsed.as_millis()).unwrap_or(u64::MAX),
    );
    // The breaker judges the exchange's final outcome: retries mask
    // individual address failures (health checking handles those), so a
    // request that ultimately succeeded is not evidence against the route.
    let breaker = target.breaker.as_deref();
    let mut resp = match outcome {
        Ok(Ok(mut resp)) => {
            if let Some(breaker) = breaker {
                if resp.status().is_server_error() {
                    breaker.record_failure();
                } else {
                    breaker.record_success();
                }
            }
            rewrite::strip_hop_by_hop_headers(resp.headers_mut());
            resp.map(ProxyBody::new)
        }
        // A request body that blew its API's size limit fails the upstream
        // send from the inside; surface that as 413, not a bogus 502. The
        // client's fault, so the breaker records nothing.
        Ok(Err(AttemptError::Client(err))) if g2_middleware::is_request_too_large(&err) => {
            tracing::debug!(%api_id, "request body exceeded the API's size limit mid-stream");
            error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
        }
        Ok(Err(AttemptError::Client(err))) => {
            if let Some(breaker) = breaker {
                breaker.record_failure();
            }
            tracing::warn!(%api_id, error = %err, "upstream request failed");
            error_response(StatusCode::BAD_GATEWAY, "upstream request failed")
        }
        // A config/request mismatch, not upstream weather: no record.
        Ok(Err(AttemptError::BadUri)) => {
            error_response(StatusCode::BAD_GATEWAY, "invalid upstream request")
        }
        Err(_elapsed) => {
            if let Some(breaker) = breaker {
                breaker.record_failure();
            }
            tracing::warn!(%api_id, timeout_ms = target.timeout.as_millis(), "upstream timed out");
            error_response(StatusCode::GATEWAY_TIMEOUT, "upstream request timed out")
        }
    };
    // Stamped on every upstream-leg outcome (502/504 included) so outer
    // layers can attribute latency to the upstream leg.
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
    fn next_addr_skips_evicted_targets_and_fails_open() {
        let def: ApiDefinition = serde_json::from_str(
            r#"{"api_id":"hc","name":"hc","listen_path":"/hc/",
                "target_url":"http://unused.internal",
                "target_list":["http://a.internal","http://b.internal","http://c.internal"],
                "health_check":{}}"#,
        )
        .expect("def");
        let target = UpstreamTarget::build(&def).expect("target");
        let health = target.health.as_ref().expect("health state built");
        assert_eq!(target.target_health(), Some(vec![true, true, true]));

        // Evicting `b` leaves the healthy pair round-robining.
        health.set_healthy(1, false);
        let hosts: Vec<&str> = (0..4)
            .map(|_| target.next_addr().authority.host())
            .collect();
        assert_eq!(
            hosts,
            ["a.internal", "c.internal", "a.internal", "c.internal"]
        );

        // With every address evicted, requests fall open to the rotation
        // instead of having nowhere to go.
        health.set_healthy(0, false);
        health.set_healthy(2, false);
        let hosts: Vec<&str> = (0..3)
            .map(|_| target.next_addr().authority.host())
            .collect();
        assert!(
            hosts.iter().all(|h| h.ends_with(".internal")),
            "fail-open must still pick real addresses, got {hosts:?}"
        );
    }

    #[test]
    fn versioned_base_target_gets_no_health_state() {
        let def: ApiDefinition = serde_json::from_str(
            r#"{"api_id":"v","name":"v","listen_path":"/v/",
                "target_url":"http://v1.internal",
                "target_list":["http://a.internal","http://b.internal"],
                "health_check":{},
                "versioning":{"default_version":"v1","versions":{"v1":{}}}}"#,
        )
        .expect("def");
        let base = UpstreamTarget::build(&def).expect("target");
        assert!(
            base.target_health().is_none(),
            "the unused base target of a versioned API must not report health"
        );
        // …while the version's effective (unversioned) definition does.
        let vdef = def
            .versioning
            .as_ref()
            .expect("versioning")
            .apply(&def, "v1")
            .expect("v1 configured");
        let vtarget = UpstreamTarget::build(&vdef).expect("target");
        assert_eq!(vtarget.target_health(), Some(vec![true, true]));
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

    /// Serves the given status on every request; returns the bound address.
    async fn spawn_status_upstream(status: StatusCode) -> SocketAddr {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
        spawn_toggle_upstream(status, flag).await
    }

    /// Serves `status` while `up` is `true`, else `500`.
    async fn spawn_toggle_upstream(
        status: StatusCode,
        up: Arc<std::sync::atomic::AtomicBool>,
    ) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let up = Arc::clone(&up);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |_req| {
                        let healthy = up.load(std::sync::atomic::Ordering::Relaxed);
                        async move {
                            let mut resp = Response::new(http_body_util::Full::new(
                                bytes::Bytes::from_static(b"upstream"),
                            ));
                            *resp.status_mut() = if healthy {
                                status
                            } else {
                                StatusCode::INTERNAL_SERVER_ERROR
                            };
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        addr
    }

    /// A port with nothing listening behind it.
    async fn dead_addr() -> SocketAddr {
        let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = dead.local_addr().expect("addr");
        drop(dead);
        addr
    }

    fn build_target(json: &str) -> Arc<UpstreamTarget> {
        let def: ApiDefinition = serde_json::from_str(json).expect("def");
        Arc::new(UpstreamTarget::build(&def).expect("target"))
    }

    async fn get_status(svc: &Forward, path: &str) -> StatusCode {
        let req = Request::builder()
            .uri(path)
            .body(ProxyBody::empty())
            .expect("request");
        svc.clone().oneshot(req).await.expect("infallible").status()
    }

    #[tokio::test]
    async fn retries_idempotent_requests_against_the_next_address() {
        let dead = dead_addr().await;
        let live = spawn_status_upstream(StatusCode::OK).await;
        let target = build_target(&format!(
            r#"{{"api_id":"r","name":"r","listen_path":"/r/",
                "target_url":"http://unused.internal",
                "target_list":["http://{dead}","http://{live}"],
                "upstream_retries":1}}"#
        ));
        let svc = Forward::new(&Forwarder::new(), target);

        // Whichever address the rotation offers first, a dead pick is
        // retried against the other — every GET succeeds.
        for _ in 0..4 {
            assert_eq!(get_status(&svc, "/r/x").await, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn non_idempotent_and_streamed_requests_are_not_retried() {
        let dead = dead_addr().await;
        let live = spawn_status_upstream(StatusCode::OK).await;
        let target = build_target(&format!(
            r#"{{"api_id":"r","name":"r","listen_path":"/r/",
                "target_url":"http://unused.internal",
                "target_list":["http://{dead}","http://{live}"],
                "upstream_retries":1}}"#
        ));
        let svc = Forward::new(&Forwarder::new(), target);

        // POST is not idempotent: the dead first pick answers 502, the live
        // second pick 200 (rotation is deterministic).
        let post = |body: ProxyBody| {
            Request::builder()
                .method(Method::POST)
                .uri("/r/x")
                .body(body)
                .expect("request")
        };
        let resp = svc
            .clone()
            .oneshot(post(ProxyBody::empty()))
            .await
            .expect("infallible");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "POST must not be retried"
        );
        let resp = svc
            .clone()
            .oneshot(post(ProxyBody::empty()))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);

        // PUT is idempotent, but a non-empty body cannot be replayed: the
        // dead third pick answers 502 despite the configured retry.
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/r/x")
            .body(ProxyBody::new(http_body_util::Full::new(
                bytes::Bytes::from_static(b"payload"),
            )))
            .expect("request");
        let resp = svc.clone().oneshot(req).await.expect("infallible");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "streamed PUT must not be retried"
        );
    }

    #[tokio::test]
    async fn circuit_opens_on_consecutive_failures_and_recovers() {
        let up = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let addr = spawn_toggle_upstream(StatusCode::OK, Arc::clone(&up)).await;
        let target = build_target(&format!(
            r#"{{"api_id":"cb","name":"cb","listen_path":"/cb/",
                "target_url":"http://{addr}",
                "circuit_breaker":{{"failure_threshold":2,"cooldown_ms":100}}}}"#
        ));
        assert_eq!(target.breaker_state(), Some("closed"));
        let svc = Forward::new(&Forwarder::new(), Arc::clone(&target));

        // Two upstream 500s trip the circuit; the third request is shed
        // with 503 without an upstream exchange.
        assert_eq!(
            get_status(&svc, "/cb/x").await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            get_status(&svc, "/cb/x").await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(target.breaker_state(), Some("open"));
        assert_eq!(
            get_status(&svc, "/cb/x").await,
            StatusCode::SERVICE_UNAVAILABLE
        );

        // After the cooldown a healthy upstream closes the circuit again.
        up.store(true, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(get_status(&svc, "/cb/x").await, StatusCode::OK);
        assert_eq!(target.breaker_state(), Some("closed"));
        assert_eq!(get_status(&svc, "/cb/x").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn failed_trial_reopens_the_circuit() {
        let dead = dead_addr().await;
        let target = build_target(&format!(
            r#"{{"api_id":"cb","name":"cb","listen_path":"/cb/",
                "target_url":"http://{dead}",
                "circuit_breaker":{{"failure_threshold":1,"cooldown_ms":100}}}}"#
        ));
        let svc = Forward::new(&Forwarder::new(), Arc::clone(&target));

        assert_eq!(get_status(&svc, "/cb/x").await, StatusCode::BAD_GATEWAY);
        assert_eq!(
            get_status(&svc, "/cb/x").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        // The trial hits the still-dead upstream (502) and re-opens.
        assert_eq!(get_status(&svc, "/cb/x").await, StatusCode::BAD_GATEWAY);
        assert_eq!(target.breaker_state(), Some("open"));
        assert_eq!(
            get_status(&svc, "/cb/x").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn versioned_base_target_gets_no_breaker() {
        let def: ApiDefinition = serde_json::from_str(
            r#"{"api_id":"v","name":"v","listen_path":"/v/",
                "target_url":"http://v1.internal",
                "circuit_breaker":{},
                "versioning":{"default_version":"v1","versions":{"v1":{}}}}"#,
        )
        .expect("def");
        let base = UpstreamTarget::build(&def).expect("target");
        assert!(base.breaker_state().is_none());
        // …while the version's effective (unversioned) definition does.
        let vdef = def
            .versioning
            .as_ref()
            .expect("versioning")
            .apply(&def, "v1")
            .expect("v1 configured");
        let vtarget = UpstreamTarget::build(&vdef).expect("target");
        assert_eq!(vtarget.breaker_state(), Some("closed"));
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

    /// Serves every request with the given status and body.
    async fn spawn_fixed_upstream(status: StatusCode, body: bytes::Bytes) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |_req| {
                        let body = body.clone();
                        async move {
                            let mut resp = Response::new(http_body_util::Full::new(body));
                            *resp.status_mut() = status;
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn jwks_fetch_returns_the_body_on_success() {
        let addr =
            spawn_fixed_upstream(StatusCode::OK, bytes::Bytes::from_static(b"{\"keys\":[]}")).await;
        let fetch = HttpJwksFetch::new(&Forwarder::new());
        let body = g2_middleware::JwksFetch::fetch(&fetch, &format!("http://{addr}/jwks.json"))
            .await
            .expect("fetch succeeds");
        assert_eq!(&body[..], b"{\"keys\":[]}");
    }

    #[tokio::test]
    async fn jwks_fetch_rejects_non_success_and_unreachable() {
        let addr = spawn_fixed_upstream(
            StatusCode::INTERNAL_SERVER_ERROR,
            bytes::Bytes::from_static(b"oops"),
        )
        .await;
        let fetch = HttpJwksFetch::new(&Forwarder::new());
        let err = g2_middleware::JwksFetch::fetch(&fetch, &format!("http://{addr}/jwks.json"))
            .await
            .expect_err("500 is an error");
        assert!(err.contains("500"), "error names the status: {err}");

        // Bind-then-drop for a dead port.
        let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let dead_addr = dead.local_addr().expect("addr");
        drop(dead);
        let err = g2_middleware::JwksFetch::fetch(&fetch, &format!("http://{dead_addr}/jwks.json"))
            .await
            .expect_err("unreachable is an error");
        assert!(err.contains("fetch failed"), "{err}");
    }

    #[tokio::test]
    async fn jwks_fetch_rejects_oversized_bodies() {
        let addr = spawn_fixed_upstream(
            StatusCode::OK,
            bytes::Bytes::from(vec![b'x'; MAX_JWKS_BYTES + 1]),
        )
        .await;
        let fetch = HttpJwksFetch::new(&Forwarder::new());
        let err = g2_middleware::JwksFetch::fetch(&fetch, &format!("http://{addr}/jwks.json"))
            .await
            .expect_err("oversized body is an error");
        assert!(err.contains("body"), "{err}");
    }
}
