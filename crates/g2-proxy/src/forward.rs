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

use arc_swap::ArcSwap;
use g2_core::{ApiDefinition, Error};
use g2_middleware::{ClientAddr, ConnectionInfo, ProxyBody};
use http::header::{HeaderValue, CONNECTION, TE, UPGRADE};
use http::uri::{Authority, Scheme, Uri};
use http::{Method, Request, Response, StatusCode, Version};
use http_body::Body as _;
use hyper_rustls::{ConfigBuilderExt as _, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Precomputes the parts of one target URL: an absolute `http`/`https`
    /// URL with a host. The fallible twin of [`Self::from_url`], for URLs
    /// that did not come from a validated definition (service discovery
    /// resolves them at runtime).
    pub(crate) fn try_from_url(url: &str) -> Result<Self, String> {
        let uri: Uri = url
            .parse()
            .map_err(|e| format!("`{url}` is not a valid URL: {e}"))?;
        let scheme = match uri.scheme() {
            Some(s) if s == &Scheme::HTTP || s == &Scheme::HTTPS => s.clone(),
            _ => return Err(format!("`{url}` must be an absolute http/https URL")),
        };
        let Some(authority) = uri.authority() else {
            return Err(format!("`{url}` must include a host"));
        };
        Ok(Self {
            scheme,
            authority: authority.clone(),
            base_path: uri.path().trim_end_matches('/').to_owned(),
        })
    }

    /// Precomputes the parts of one target URL.
    ///
    /// # Panics
    ///
    /// Panics if `url` has not passed [`ApiDefinition::validate`]'s target
    /// URL checks; callers must validate the definition first.
    fn from_url(url: &str) -> Self {
        Self::try_from_url(url).expect("target URL validated")
    }
}

/// One coherent generation of an API's upstream addresses, with the health
/// flags that belong to exactly those addresses.
///
/// A target's set is replaced wholesale when service discovery resolves a
/// different address list (see [`crate::discovery`]); bundling the flags
/// with the addresses makes the flags-index-matches-address invariant
/// structural instead of implicit. A fresh set starts all-healthy, like a
/// freshly built route.
#[derive(Debug)]
pub(crate) struct TargetSet {
    /// The upstream addresses requests are forwarded to. Never empty: the
    /// definition's `target_list` when configured, else its single
    /// `target_url`; service discovery rejects empty results.
    pub(crate) addrs: Vec<UpstreamAddr>,
    /// Per-address health flags written by the checker task (see
    /// [`crate::health`]); present iff health checking is active for the
    /// owning target.
    pub(crate) health: Option<HealthState>,
}

impl TargetSet {
    /// A set over `addrs`, all healthy, carrying health state iff
    /// `health_checked`.
    pub(crate) fn new(addrs: Vec<UpstreamAddr>, health_checked: bool) -> Self {
        let health = health_checked.then(|| HealthState::new(addrs.len()));
        Self { addrs, health }
    }

    /// The address the next request should use: round-robin via `cursor`,
    /// skipping addresses evicted by health checking — the healthy subset
    /// keeps round-robining — but eviction never empties the pool: with
    /// every address evicted, the plain rotation is used (fail open; a dead
    /// upstream then answers `502` like an unchecked one).
    ///
    /// Single-address sets skip the atomic entirely, so unbalanced routes
    /// pay nothing for this feature. The cursor wraps at `usize::MAX`, which
    /// can skip ahead in the rotation once per ~2^64 requests — harmless.
    pub(crate) fn next_addr(&self, cursor: &AtomicUsize) -> &UpstreamAddr {
        let count = self.addrs.len();
        if count == 1 {
            return &self.addrs[0];
        }
        for _ in 0..count {
            let index = cursor.fetch_add(1, Ordering::Relaxed) % count;
            if self
                .health
                .as_ref()
                .is_none_or(|health| health.is_healthy(index))
            {
                return &self.addrs[index];
            }
        }
        let index = cursor.fetch_add(1, Ordering::Relaxed) % count;
        &self.addrs[index]
    }
}

/// Everything about an API's upstream precomputed at route-build time so
/// forwarding does no per-request parsing.
///
/// Structurally immutable — built once per route table — except for one
/// designated swappable leaf: the target set holding the current upstream
/// addresses, which service discovery may replace wholesale between reloads
/// (ADR-0006). Reads stay lock-free and allocation-free.
#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    /// The `api_id` of the API definition (for logs and error context).
    pub api_id: String,
    /// `listen_path` with any trailing `/` removed (`"/users"`; empty for `"/"`).
    pub listen_prefix: String,
    /// The current generation of upstream addresses (+ their health flags).
    /// Seeded from the definition's `target_list`/`target_url`; shared
    /// across clones (like [`Self::next_target`]) so a discovery swap
    /// reaches every handle.
    targets: Arc<ArcSwap<TargetSet>>,
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
    /// Round-robin cursor over the current target set, shared across clones
    /// so every handle to this target advances one rotation.
    next_target: Arc<AtomicUsize>,
    /// Per-route circuit state read and written by the forwarder (see
    /// [`crate::breaker`]); present iff the definition enables breaking and
    /// this target forwards traffic (the base target of a versioned API
    /// does not — each version carries its own target).
    pub(crate) breaker: Option<Arc<CircuitBreaker>>,
    /// Live service-discovery status for dashboards (see
    /// [`crate::discovery`]); present under the same conditions as
    /// `breaker`.
    pub(crate) discovery: Option<Arc<crate::discovery::DiscoveryStatus>>,
    /// Additional forwarding attempts after a transport failure, for
    /// idempotent empty-body requests only.
    pub(crate) retries: u32,
    /// Whether `Connection: Upgrade` requests (WebSocket) are tunneled
    /// through to the upstream instead of being downgraded to plain HTTP.
    pub(crate) upgrades_enabled: bool,
    /// Whether upstream requests are sent over HTTP/2 (h2c prior knowledge
    /// on `http://`, ALPN `h2` on `https://`) instead of HTTP/1.1 — the
    /// gRPC-passthrough switch. Picks the forwarder's HTTP/2-only client.
    pub(crate) http2: bool,
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
        // target), so only unversioned definitions get live health,
        // circuit, and discovery state.
        let forwards = def.versioning.is_none();
        let health_checked = forwards && def.health_check.is_some();
        let breaker = if forwards {
            def.circuit_breaker
                .as_ref()
                .map(|cfg| Arc::new(CircuitBreaker::new(cfg, &def.api_id)))
        } else {
            None
        };
        let discovery = if forwards {
            def.service_discovery
                .as_ref()
                .map(|_| Arc::new(crate::discovery::DiscoveryStatus::default()))
        } else {
            None
        };
        Ok(Self {
            api_id: def.api_id.clone(),
            listen_prefix: def.listen_path.trim_end_matches('/').to_owned(),
            targets: Arc::new(ArcSwap::from_pointee(TargetSet::new(
                targets,
                health_checked,
            ))),
            strip_listen_path: def.strip_listen_path,
            preserve_host_header: def.preserve_host_header,
            timeout: Duration::from_millis(def.upstream_timeout_ms),
            rewrites,
            method_override,
            next_target: Arc::new(AtomicUsize::new(0)),
            breaker,
            discovery,
            retries: def.upstream_retries,
            upgrades_enabled: def.enable_upgrades,
            http2: def.upstream_http2,
        })
    }

    /// The current target set, as a cheap wait-free load guard. Round-robin
    /// address selection is pod-local (no cross-pod coordination — each
    /// gateway process keeps its own rotation):
    /// `target.target_set().next_addr(target.cursor())`.
    ///
    /// Hold the guard only briefly (address pick + URI assembly) — a
    /// long-held guard pins a stale set alive across discovery swaps.
    pub(crate) fn target_set(&self) -> arc_swap::Guard<Arc<TargetSet>> {
        self.targets.load()
    }

    /// The current target set as an owned `Arc`, for background tasks that
    /// hold it across await points (health checker, discovery refresher).
    pub(crate) fn target_set_full(&self) -> Arc<TargetSet> {
        self.targets.load_full()
    }

    /// Replaces the target set wholesale (service discovery). The rotation
    /// cursor is deliberately left running — its modulo changes with the
    /// address count, which at worst skips ahead in the new rotation.
    pub(crate) fn store_target_set(&self, set: Arc<TargetSet>) {
        self.targets.store(set);
    }

    /// The round-robin cursor accompanying [`Self::target_set`].
    pub(crate) fn cursor(&self) -> &AtomicUsize {
        &self.next_target
    }

    /// Health of each address in the current target set, in order; `None`
    /// when health checking is not active for this target (unconfigured, or
    /// the unused base target of a versioned API). For status/dashboard APIs.
    #[must_use]
    pub fn target_health(&self) -> Option<Vec<bool>> {
        self.targets
            .load()
            .health
            .as_ref()
            .map(HealthState::snapshot)
    }

    /// The addresses currently in the load-balancing rotation, rendered as
    /// URLs. Equals the definition's `target_list`/`target_url` until
    /// service discovery swaps in a resolved set. For status/dashboard APIs.
    #[must_use]
    pub fn live_targets(&self) -> Vec<String> {
        self.targets
            .load()
            .addrs
            .iter()
            .map(|addr| format!("{}://{}{}", addr.scheme, addr.authority, addr.base_path))
            .collect()
    }

    /// A snapshot of the service-discovery status; `None` when discovery is
    /// not active for this target (unconfigured, or the unused base target
    /// of a versioned API). For status/dashboard APIs.
    #[must_use]
    pub fn discovery_status(&self) -> Option<crate::discovery::DiscoverySnapshot> {
        self.discovery.as_ref().map(|status| status.snapshot())
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

/// Process-wide handle to the pooled upstream HTTP clients.
///
/// Cheap to clone — clones share the connection pools — so a single
/// `Forwarder` created at startup is passed to every
/// [`RouteTable::build`](crate::RouteTable::build), and upstream connections
/// survive config hot reloads.
///
/// Two pools live here because hyper's client pins its protocol per pool:
/// the default HTTP/1.1 client, and an HTTP/2-only client for APIs with
/// `upstream_http2` (h2c prior knowledge on `http://`, ALPN offering only
/// `h2` on `https://`).
#[derive(Debug, Clone)]
pub struct Forwarder {
    client: UpstreamClient,
    h2_client: UpstreamClient,
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
        // Each connector gets its own copy of the TLS config: the builder's
        // protocol selection writes the config's ALPN list (`enable_http1`
        // leaves it empty, `enable_http2` sets `["h2"]`), so sharing one
        // config would poison the other connector's negotiation.
        let h1_connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http()
            .enable_http1()
            .build();
        let h2_connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http2()
            .build();
        Self {
            client: Client::builder(TokioExecutor::new()).build(h1_connector),
            // `http2_only` is what turns plaintext connections into h2c
            // prior-knowledge ones; TLS connections already negotiate `h2`
            // via the connector's ALPN.
            h2_client: Client::builder(TokioExecutor::new())
                .http2_only(true)
                .build(h2_connector),
        }
    }

    /// The shared HTTP/1.1 pooled client (JWKS fetches reuse it).
    pub(crate) fn client(&self) -> &UpstreamClient {
        &self.client
    }

    /// The pooled client matching `target`'s upstream protocol. Forwarding
    /// and health-check probes both pick their client here, so an HTTP/2
    /// API's probes reach upstreams that reject HTTP/1.1.
    pub(crate) fn client_for(&self, target: &UpstreamTarget) -> &UpstreamClient {
        if target.http2 {
            &self.h2_client
        } else {
            &self.client
        }
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
    /// Creates the forwarding service for `target` using `forwarder`'s
    /// client for the target's upstream protocol.
    pub(crate) fn new(forwarder: &Forwarder, target: Arc<UpstreamTarget>) -> Self {
        Self {
            client: forwarder.client_for(&target).clone(),
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
        // The set guard lives only for URI assembly: a long-held guard would
        // pin a stale set alive across discovery swaps.
        let upstream_uri = {
            let set = target.target_set();
            let addr = set.next_addr(target.cursor());
            let path_and_query =
                rewrite::upstream_path_and_query(target, addr, parts.uri.path(), parts.uri.query());
            Uri::builder()
                .scheme(addr.scheme.clone())
                .authority(addr.authority.clone())
                .path_and_query(path_and_query)
                .build()
        };
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
    // Whether the gateway terminated TLS on this connection; drives the
    // `X-Forwarded-Proto` value. Absent extension means a plaintext caller.
    let tls = req
        .extensions()
        .get::<ConnectionInfo>()
        .is_some_and(|conn| conn.tls);

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
    // An upgrade passthrough is attempted only when the API opted in, the
    // client asked (an `Upgrade` header), and the client connection can
    // actually switch protocols (hyper stamped an `OnUpgrade` extension —
    // absent on HTTP/2 requests, whose streams cannot carry an HTTP/1.1
    // upgrade). Everything else proxies as plain HTTP.
    let upgrade = if target.upgrades_enabled {
        parts.headers.get(UPGRADE).cloned().and_then(|protocol| {
            parts
                .extensions
                .remove::<hyper::upgrade::OnUpgrade>()
                .map(|client| (protocol, client))
        })
    } else {
        None
    };
    // The upstream connection is negotiated by the client independently
    // of the client-facing protocol version; the version stamped here only
    // has to match the chosen client's protocol.
    parts.version = if target.http2 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    // gRPC requires `te: trailers` end to end, but `te` is hop-by-hop and
    // about to be stripped. It is also the only `te` value HTTP/2 permits
    // (RFC 9113 §8.2.2), so anything else stays stripped.
    let keep_te = target.http2
        && parts
            .headers
            .get(TE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
            });
    rewrite::prepare_upstream_headers(&mut parts.headers, target, client_ip, tls);
    if keep_te {
        parts
            .headers
            .insert(TE, HeaderValue::from_static("trailers"));
    }
    if let Some((protocol, _)) = &upgrade {
        // Hop-by-hop stripping just removed the upgrade headers; a request
        // asking the upstream to switch protocols must carry them.
        parts
            .headers
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        parts.headers.insert(UPGRADE, protocol.clone());
    }
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
            if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                match upgrade {
                    Some((_, client)) => upgrade_response(api_id, client, resp),
                    // The upstream switched protocols unasked (the forwarded
                    // request carried no upgrade headers): there is no client
                    // side to splice it to, so the exchange is unusable.
                    None => {
                        tracing::warn!(%api_id, "upstream answered 101 to a non-upgrade request");
                        error_response(
                            StatusCode::BAD_GATEWAY,
                            "unexpected upgrade response from upstream",
                        )
                    }
                }
            } else {
                rewrite::strip_hop_by_hop_headers(resp.headers_mut());
                resp.map(ProxyBody::new)
            }
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

/// Accepts an upstream `101 Switching Protocols` answer to a tunneled
/// upgrade request: spawns the task that splices the two connections
/// together once both sides complete their protocol switch, and returns the
/// `101` (upgrade headers intact) that makes hyper hand the client
/// connection over to that task.
///
/// The tunnel outlives the request: it runs until either side closes (or
/// the process exits — tunnels are not part of the graceful drain), and the
/// bytes inside it are opaque to the gateway. The per-API upstream timeout
/// only ever covered the upgrade handshake, which has completed here.
fn upgrade_response(
    api_id: &str,
    client: hyper::upgrade::OnUpgrade,
    mut resp: Response<hyper::body::Incoming>,
) -> Response<ProxyBody> {
    let protocol = resp.headers().get(UPGRADE).cloned();
    let upstream = hyper::upgrade::on(&mut resp);
    let api_id = api_id.to_owned();
    tokio::spawn(async move {
        // The client side resolves once hyper has written the 101 returned
        // below; the upstream side is typically ready already.
        let (client_io, upstream_io) = match tokio::try_join!(client, upstream) {
            Ok(io) => io,
            Err(err) => {
                tracing::debug!(%api_id, error = %err, "connection upgrade failed");
                return;
            }
        };
        let (mut client_io, mut upstream_io) = (TokioIo::new(client_io), TokioIo::new(upstream_io));
        match tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
            Ok((sent, received)) => {
                tracing::debug!(%api_id, sent, received, "upgrade tunnel closed");
            }
            Err(err) => tracing::debug!(%api_id, error = %err, "upgrade tunnel ended with error"),
        }
    });
    // The upgrade headers are hop-by-hop but load-bearing on a 101: put
    // them back after the standard strip so the client completes its
    // protocol switch.
    rewrite::strip_hop_by_hop_headers(resp.headers_mut());
    let mut resp = resp.map(ProxyBody::new);
    resp.headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("upgrade"));
    if let Some(protocol) = protocol {
        resp.headers_mut().insert(UPGRADE, protocol);
    }
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

    /// Echoes the request's protocol version and `te` header into response
    /// headers, and answers with a gRPC-shaped body: one data frame followed
    /// by a `grpc-status: 0` trailer frame.
    async fn grpc_style_service(
        req: Request<hyper::body::Incoming>,
    ) -> Result<
        Response<
            http_body_util::StreamBody<
                futures_util::stream::Iter<
                    std::vec::IntoIter<Result<http_body::Frame<bytes::Bytes>, Infallible>>,
                >,
            >,
        >,
        Infallible,
    > {
        let version = format!("{:?}", req.version());
        let te = req
            .headers()
            .get(TE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<none>")
            .to_owned();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let frames = vec![
            Ok(http_body::Frame::data(bytes::Bytes::from_static(
                b"grpc ok",
            ))),
            Ok(http_body::Frame::trailers(trailers)),
        ];
        let body = http_body_util::StreamBody::new(futures_util::stream::iter(frames));
        Ok(Response::builder()
            .header("x-seen-version", version)
            .header("x-seen-te", te)
            .body(body)
            .expect("response"))
    }

    /// Serves [`grpc_style_service`] over plaintext HTTP/2 (h2c prior
    /// knowledge only — an HTTP/1.1 request fails the connection).
    async fn spawn_h2c_upstream() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(stream),
                            hyper::service::service_fn(grpc_style_service),
                        )
                        .await;
                });
            }
        });
        addr
    }

    /// Serves [`grpc_style_service`] over plain HTTP/1.1.
    async fn spawn_h1_echo_upstream() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            hyper::service::service_fn(grpc_style_service),
                        )
                        .await;
                });
            }
        });
        addr
    }

    fn plain_target(addr: SocketAddr, upstream_http2: bool) -> Arc<UpstreamTarget> {
        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"grpc","name":"grpc","listen_path":"/grpc/",
                "target_url":"http://127.0.0.1:{}","upstream_http2":{upstream_http2}}}"#,
            addr.port()
        ))
        .expect("def");
        Arc::new(UpstreamTarget::build(&def).expect("target"))
    }

    #[tokio::test]
    async fn h2c_upstream_gets_http2_te_and_returns_trailers() {
        let addr = spawn_h2c_upstream().await;
        let svc = Forward::new(&Forwarder::new(), plain_target(addr, true));

        let req = Request::builder()
            .method(Method::POST)
            .uri("/grpc/pkg.Svc/Method")
            .header(TE, "trailers")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-seen-version"], "HTTP/2.0");
        assert_eq!(resp.headers()["x-seen-te"], "trailers");
        let collected = resp.into_body().collect().await.expect("body");
        let trailers = collected.trailers().cloned().expect("trailers forwarded");
        assert_eq!(trailers["grpc-status"], "0");
        assert_eq!(&collected.to_bytes()[..], b"grpc ok");
    }

    #[tokio::test]
    async fn h2_flag_off_keeps_upstream_http11_and_strips_te() {
        let addr = spawn_h1_echo_upstream().await;
        let svc = Forward::new(&Forwarder::new(), plain_target(addr, false));

        let req = Request::builder()
            .uri("/grpc/x")
            .header(TE, "trailers")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-seen-version"], "HTTP/1.1");
        assert_eq!(resp.headers()["x-seen-te"], "<none>");
    }

    #[tokio::test]
    async fn te_without_trailers_token_is_not_resurrected() {
        let addr = spawn_h2c_upstream().await;
        let svc = Forward::new(&Forwarder::new(), plain_target(addr, true));

        let req = Request::builder()
            .uri("/grpc/x")
            .header(TE, "gzip")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-seen-te"], "<none>");
    }

    #[tokio::test]
    async fn https_upstream_negotiates_h2_via_alpn() {
        // An upstream that only accepts `h2` over TLS: negotiation succeeds
        // only when the forwarder's HTTP/2 connector offers it via ALPN.
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("self-signed cert");
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).expect("trust anchor");
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        server_config.alpn_protocols = vec![b"h2".to_vec()];
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
                        return;
                    };
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(tls),
                            hyper::service::service_fn(grpc_style_service),
                        )
                        .await;
                });
            }
        });

        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"grpcs","name":"grpcs","listen_path":"/grpcs/",
                "target_url":"https://localhost:{}","upstream_http2":true}}"#,
            addr.port()
        ))
        .expect("def");
        let target = Arc::new(UpstreamTarget::build(&def).expect("target"));
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let svc = Forward::new(&Forwarder::with_tls_config(tls), target);

        let req = Request::builder()
            .uri("/grpcs/x")
            .header(TE, "trailers")
            .body(ProxyBody::empty())
            .expect("request");
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-seen-version"], "HTTP/2.0");
        let collected = resp.into_body().collect().await.expect("body");
        assert_eq!(
            collected.trailers().expect("trailers forwarded")["grpc-status"],
            "0"
        );
    }

    /// The next round-robin pick's host, owned (tests only — the hot path
    /// borrows through the guard instead).
    fn pick(target: &UpstreamTarget) -> String {
        let set = target.target_set();
        set.next_addr(target.cursor()).authority.host().to_owned()
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

        let hosts: Vec<String> = (0..4).map(|_| pick(&target)).collect();
        assert_eq!(
            hosts,
            ["a.internal", "b.internal", "c.internal", "a.internal"]
        );

        // Clones share the cursor: the rotation continues, never restarts.
        let clone = target.clone();
        assert_eq!(pick(&clone), "b.internal");
        assert_eq!(pick(&target), "c.internal");
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
        assert_eq!(target.target_health(), Some(vec![true, true, true]));

        // Evicting `b` leaves the healthy pair round-robining.
        let set = target.target_set_full();
        let health = set.health.as_ref().expect("health state built");
        health.set_healthy(1, false);
        let hosts: Vec<String> = (0..4).map(|_| pick(&target)).collect();
        assert_eq!(
            hosts,
            ["a.internal", "c.internal", "a.internal", "c.internal"]
        );

        // With every address evicted, requests fall open to the rotation
        // instead of having nowhere to go.
        health.set_healthy(0, false);
        health.set_healthy(2, false);
        let hosts: Vec<String> = (0..3).map(|_| pick(&target)).collect();
        assert!(
            hosts.iter().all(|h| h.ends_with(".internal")),
            "fail-open must still pick real addresses, got {hosts:?}"
        );
    }

    #[test]
    fn swapping_the_target_set_redirects_the_rotation() {
        let def: ApiDefinition = serde_json::from_str(
            r#"{"api_id":"sd","name":"sd","listen_path":"/sd/",
                "target_url":"http://unused.internal",
                "target_list":["http://a.internal","http://b.internal"],
                "health_check":{}}"#,
        )
        .expect("def");
        let target = UpstreamTarget::build(&def).expect("target");
        assert_eq!(pick(&target), "a.internal");

        // A discovery-style swap: every subsequent pick uses the new set,
        // and the fresh health state starts all-healthy.
        let swapped = TargetSet::new(
            vec![UpstreamAddr::try_from_url("http://x.internal:7000").expect("valid")],
            target.target_set().health.is_some(),
        );
        target.store_target_set(Arc::new(swapped));
        for _ in 0..3 {
            assert_eq!(pick(&target), "x.internal");
        }
        assert_eq!(target.target_health(), Some(vec![true]));
        assert_eq!(target.live_targets(), ["http://x.internal:7000"]);
    }

    #[test]
    fn try_from_url_rejects_bad_schemes_and_missing_hosts() {
        assert!(UpstreamAddr::try_from_url("http://ok.internal/base").is_ok());
        assert!(UpstreamAddr::try_from_url("https://ok.internal:8443").is_ok());
        for bad in ["ftp://x.internal", "/relative", "not a url", "http://"] {
            assert!(UpstreamAddr::try_from_url(bad).is_err(), "`{bad}` accepted");
        }
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
        assert_eq!(target.target_set().addrs.len(), 1);
        for _ in 0..3 {
            let set = target.target_set();
            assert_eq!(
                set.next_addr(target.cursor()).authority.as_str(),
                "only.internal:8080"
            );
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

    #[test]
    fn upgrades_enabled_flag_comes_from_the_definition() {
        let def: ApiDefinition = serde_json::from_str(
            r#"{"api_id":"u","name":"u","listen_path":"/u/",
                "target_url":"http://u.internal","enable_upgrades":true}"#,
        )
        .expect("def");
        assert!(
            UpstreamTarget::build(&def)
                .expect("target")
                .upgrades_enabled
        );
        let def: ApiDefinition = serde_json::from_str(
            r#"{"api_id":"u","name":"u","listen_path":"/u/","target_url":"http://u.internal"}"#,
        )
        .expect("def");
        assert!(
            !UpstreamTarget::build(&def)
                .expect("target")
                .upgrades_enabled
        );
    }

    #[tokio::test]
    async fn unsolicited_upstream_101_maps_to_502() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        // A raw upstream that answers 101 to every request, upgrade or not.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\n\
                              connection: upgrade\r\nupgrade: rawproto\r\n\r\n",
                        )
                        .await;
                });
            }
        });

        // The request never asked to upgrade (no `Upgrade` header, no
        // `OnUpgrade` extension), so the 101 is unusable.
        let target = build_target(&format!(
            r#"{{"api_id":"u","name":"u","listen_path":"/u/",
                "target_url":"http://{addr}","enable_upgrades":true}}"#
        ));
        let svc = Forward::new(&Forwarder::new(), target);
        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/u/x")
                    .body(ProxyBody::empty())
                    .expect("request"),
            )
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        assert!(
            std::str::from_utf8(&body)
                .expect("utf8")
                .contains("upgrade"),
            "error names the upgrade: {body:?}"
        );
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
