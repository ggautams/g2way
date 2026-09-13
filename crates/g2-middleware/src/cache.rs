//! [`CacheLayer`]: shared response caching for safe requests.
//!
//! Sits **below** auth, rate limiting, and the header transforms (a
//! protected API's cache hits still require credentials and consume rate,
//! and response transforms are re-applied live on every hit, so the stored
//! copy is the raw upstream response) and **below** the mock layer (mock
//! responses are already gateway-local; caching them would only spend
//! storage).
//!
//! What gets cached follows [`CacheConfig`]: safe
//! methods (`GET`/`HEAD`/`OPTIONS`) only, `2xx` responses only, never a
//! response carrying `Set-Cookie` — the cache is shared across every client
//! of the API, and a per-client response replayed to someone
//! else would be a credential leak. Hits are marked `x-g2-cache: hit`.
//!
//! Entries live in shared storage (every pod hits the same cache) under
//! `g2:{org}:cache:{scope}:{digest}` with the configured TTL, via plain
//! [`Storage::get`](g2_storage::Storage::get)/[`set`](g2_storage::Storage::set).
//! Like the rate limiter, storage failures **fail open**: a broken Redis
//! makes every request a miss, it never rejects traffic.
//!
//! A miss adds no latency and no response buffering: the upstream body is
//! streamed to the client unchanged through a recording wrapper, and only
//! when the stream completes cleanly within the size cap is the entry
//! written to storage from a background task. A client that disconnects
//! mid-body, a stream error, or an oversized body simply caches nothing.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use g2_core::api_definition::response_cache_key_prefix;
use g2_core::session::hash_key;
use g2_core::CacheConfig;
use http::header::{HeaderName, HeaderValue, SET_COOKIE};
use http::{Method, Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::Full;
use serde::{Deserialize, Serialize};
use tower::{Layer, Service};

use crate::{BoxError, ProxyBody};

/// Response header marking a cache hit: `x-g2-cache: hit`. Absent on misses
/// and on responses the cache never considered.
pub const CACHE_STATUS_HEADER: &str = "x-g2-cache";

/// Everything one API's response caching needs, precomputed at route-build
/// time.
struct CacheState {
    /// `g2:{org}:cache:{scope}:` — the request digest is appended per
    /// request.
    key_prefix: String,
    ttl: Duration,
    max_body_bytes: usize,
    storage: g2_storage::SharedStorage,
}

impl std::fmt::Debug for CacheState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheState")
            .field("key_prefix", &self.key_prefix)
            .field("ttl", &self.ttl)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

/// Tower layer serving repeat safe requests from a shared response cache.
#[derive(Debug, Clone)]
pub struct CacheLayer {
    state: Arc<CacheState>,
}

impl CacheLayer {
    /// Builds the layer for one cache scope. `scope` is the API id — or
    /// `{api_id}:{version}` for one version of a versioned API, so versions
    /// with different upstreams never share entries.
    #[must_use]
    pub fn new(
        config: &CacheConfig,
        scope: &str,
        org_id: &str,
        storage: g2_storage::SharedStorage,
    ) -> Self {
        Self {
            state: Arc::new(CacheState {
                key_prefix: response_cache_key_prefix(org_id, scope),
                ttl: Duration::from_secs(config.ttl_secs),
                max_body_bytes: usize::try_from(config.max_body_bytes).unwrap_or(usize::MAX),
                storage,
            }),
        }
    }
}

impl<S> Layer<S> for CacheLayer {
    type Service = Cache<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Cache {
            inner,
            state: Arc::clone(&self.state),
        }
    }
}

/// The [`Service`] produced by [`CacheLayer`].
#[derive(Debug, Clone)]
pub struct Cache<S> {
    inner: S,
    state: Arc<CacheState>,
}

impl<S> Service<Request<ProxyBody>> for Cache<S>
where
    S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ProxyBody>) -> Self::Future {
        if !is_safe_method(req.method()) {
            return Box::pin(self.inner.call(req));
        }
        let state = Arc::clone(&self.state);
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        // The digest covers method + full path?query verbatim; the uri of a
        // proxied request is origin-form, so this is the whole request line.
        let target = req
            .uri()
            .path_and_query()
            .map_or_else(|| req.uri().path().to_owned(), ToString::to_string);
        let key = format!(
            "{}{}",
            state.key_prefix,
            hash_key(&format!("{} {target}", req.method()))
        );

        Box::pin(async move {
            match state.storage.get(&key).await {
                Ok(Some(stored)) => match decode_entry(&stored) {
                    Some(resp) => return Ok(resp),
                    None => {
                        // A corrupt entry is a miss; the fresh response
                        // overwrites it below.
                        tracing::warn!(key = %key, "corrupt cache entry ignored");
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(key = %key, error = %e, "cache lookup failed; failing open");
                }
            }

            let resp = inner.call(req).await?;
            Ok(record_if_cacheable(resp, &state, key))
        })
    }
}

/// The safe-method set that may be cached.
fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Wraps a cacheable response's body in the recording tee; anything not
/// worth caching is returned untouched.
fn record_if_cacheable(
    resp: Response<ProxyBody>,
    state: &Arc<CacheState>,
    key: String,
) -> Response<ProxyBody> {
    // Only 2xx, and never a response that sets client state: `Set-Cookie`
    // is per-client, and this cache is shared across clients.
    if !resp.status().is_success() || resp.headers().contains_key(SET_COOKIE) {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let write = CacheWrite {
        storage: Arc::clone(&state.storage),
        key,
        ttl: state.ttl,
        status: parts.status,
        headers: parts
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    };
    let recording = RecordingBody {
        inner: body,
        buf: BytesMut::new(),
        max: state.max_body_bytes,
        write: Some(write),
    };
    Response::from_parts(parts, ProxyBody::new(recording))
}

/// One cached response on the wire: JSON in storage. Header and body bytes
/// are base64 (header values and bodies need not be UTF-8).
#[derive(Serialize, Deserialize)]
struct CachedEntry {
    status: u16,
    /// `(name, base64(value bytes))` pairs, in response order.
    headers: Vec<(String, String)>,
    body_b64: String,
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Serializes a completed response for storage.
fn encode_entry(status: StatusCode, headers: &[(HeaderName, HeaderValue)], body: &[u8]) -> String {
    let entry = CachedEntry {
        status: status.as_u16(),
        headers: headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), B64.encode(value.as_bytes())))
            .collect(),
        body_b64: B64.encode(body),
    };
    serde_json::to_string(&entry).expect("cache entry serializes: plain strings and integers")
}

/// Rebuilds the response from a stored entry, marked as a hit. `None` when
/// the record does not decode (treated as a miss by the caller).
fn decode_entry(stored: &str) -> Option<Response<ProxyBody>> {
    let entry: CachedEntry = serde_json::from_str(stored).ok()?;
    let mut resp = Response::new(ProxyBody::new(Full::new(Bytes::from(
        B64.decode(&entry.body_b64).ok()?,
    ))));
    *resp.status_mut() = StatusCode::from_u16(entry.status).ok()?;
    for (name, value) in &entry.headers {
        resp.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).ok()?,
            HeaderValue::from_bytes(&B64.decode(value).ok()?).ok()?,
        );
    }
    resp.headers_mut()
        .insert(CACHE_STATUS_HEADER, HeaderValue::from_static("hit"));
    Some(resp)
}

/// Everything needed to write one entry once its body has fully streamed.
struct CacheWrite {
    storage: g2_storage::SharedStorage,
    key: String,
    ttl: Duration,
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl CacheWrite {
    /// Spawns the storage write in the background; the client's response is
    /// already complete and must not wait on Redis.
    fn spawn(self, body: &[u8]) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // Bodies are only ever driven inside the server runtime; this
            // guard just keeps exotic sync callers panic-free.
            return;
        };
        let value = encode_entry(self.status, &self.headers, body);
        handle.spawn(async move {
            if let Err(e) = self.storage.set(&self.key, &value, Some(self.ttl)).await {
                tracing::error!(key = %self.key, error = %e, "cache write failed");
            }
        });
    }
}

/// A tee around the upstream body: frames stream to the client unchanged
/// while being copied into a bounded buffer. A clean end-of-stream within
/// the cap triggers the background cache write; overflow, a stream error,
/// or an abandoned body (client gone) drops the write instead.
struct RecordingBody {
    inner: ProxyBody,
    buf: BytesMut,
    max: usize,
    /// Present while the body is still worth caching; taken on completion,
    /// dropped on overflow/error.
    write: Option<CacheWrite>,
}

impl Body for RecordingBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if this.write.is_some() {
                    if let Some(data) = frame.data_ref() {
                        if this.buf.len() + data.len() > this.max {
                            this.write = None;
                            this.buf = BytesMut::new();
                        } else {
                            this.buf.extend_from_slice(data);
                        }
                    }
                    // Trailer frames pass through to the client but are not
                    // part of the cached copy.
                }
                // A fixed-length body is often never polled again once its
                // declared length has been delivered (hyper stops at the
                // last byte), so completion must also be detected here —
                // waiting for the `None` frame would drop most writes.
                if this.inner.is_end_stream() {
                    if let Some(write) = this.write.take() {
                        write.spawn(&this.buf);
                        this.buf = BytesMut::new();
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.write = None;
                this.buf = BytesMut::new();
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                if let Some(write) = this.write.take() {
                    write.spawn(&this.buf);
                    this.buf = BytesMut::new();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use g2_storage::{MemoryStorage, SharedStorage, Storage, StorageError};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    fn config() -> CacheConfig {
        serde_json::from_str("{}").expect("defaults")
    }

    fn body(text: &'static str) -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::from_static(text.as_bytes())))
    }

    /// An inner service counting calls, answering with a configurable
    /// response per call.
    fn counting_inner(
        counter: Arc<AtomicUsize>,
        make: impl Fn() -> Response<ProxyBody> + Clone + Send + Sync + 'static,
    ) -> crate::ChainService {
        crate::ChainService::new(tower::service_fn(move |_req: Request<ProxyBody>| {
            counter.fetch_add(1, Ordering::SeqCst);
            let resp = make();
            async move { Ok(resp) }
        }))
    }

    fn service(storage: SharedStorage, inner: crate::ChainService) -> crate::ChainService {
        let layer = CacheLayer::new(&config(), "users-api", "acme", storage);
        crate::ChainService::new(layer.layer(inner))
    }

    fn request(method: &str, path: &str) -> Request<ProxyBody> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(ProxyBody::empty())
            .expect("request")
    }

    /// Waits for the background cache write to land (bounded).
    async fn await_entry(storage: &SharedStorage) {
        for _ in 0..100 {
            let keys = storage.scan_prefix("g2:acme:cache:").await.expect("scan");
            if !keys.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("cache entry never written");
    }

    #[tokio::test]
    async fn second_get_is_served_from_cache() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let count = Arc::new(AtomicUsize::new(0));
        let inner = counting_inner(Arc::clone(&count), || {
            let mut resp = Response::new(body("payload"));
            resp.headers_mut()
                .insert("content-type", HeaderValue::from_static("text/plain"));
            resp
        });

        let resp = service(Arc::clone(&storage), inner.clone())
            .oneshot(request("GET", "/x?a=1"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key(CACHE_STATUS_HEADER), "miss");
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(bytes.as_ref(), b"payload");
        await_entry(&storage).await;

        let resp = service(Arc::clone(&storage), inner)
            .oneshot(request("GET", "/x?a=1"))
            .await
            .expect("infallible");
        assert_eq!(count.load(Ordering::SeqCst), 1, "upstream hit once");
        assert_eq!(
            resp.headers()
                .get(CACHE_STATUS_HEADER)
                .expect("hit marker")
                .as_bytes(),
            b"hit"
        );
        assert_eq!(
            resp.headers().get("content-type").expect("ct").as_bytes(),
            b"text/plain"
        );
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(bytes.as_ref(), b"payload");
    }

    #[tokio::test]
    async fn method_path_and_query_are_all_part_of_the_key() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let count = Arc::new(AtomicUsize::new(0));
        let inner = counting_inner(Arc::clone(&count), || Response::new(body("ok")));

        let _ = service(Arc::clone(&storage), inner.clone())
            .oneshot(request("GET", "/x?a=1"))
            .await
            .expect("infallible")
            .into_body()
            .collect()
            .await;
        await_entry(&storage).await;

        // A different query, a different path, and a different method all
        // miss the entry above.
        for (method, path) in [("GET", "/x?a=2"), ("GET", "/y?a=1"), ("HEAD", "/x?a=1")] {
            let resp = service(Arc::clone(&storage), inner.clone())
                .oneshot(request(method, path))
                .await
                .expect("infallible");
            assert!(
                !resp.headers().contains_key(CACHE_STATUS_HEADER),
                "{method} {path} unexpectedly hit"
            );
        }
        assert_eq!(count.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn unsafe_methods_bypass_the_cache_entirely() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let count = Arc::new(AtomicUsize::new(0));
        let inner = counting_inner(Arc::clone(&count), || Response::new(body("ok")));

        for _ in 0..2 {
            let resp = service(Arc::clone(&storage), inner.clone())
                .oneshot(request("POST", "/x"))
                .await
                .expect("infallible");
            let _ = resp.into_body().collect().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(count.load(Ordering::SeqCst), 2, "every POST forwarded");
        assert!(
            storage
                .scan_prefix("g2:acme:cache:")
                .await
                .expect("scan")
                .is_empty(),
            "POST response cached"
        );
    }

    #[tokio::test]
    async fn non_2xx_and_set_cookie_responses_are_not_cached() {
        for make in [
            // 404: not a success.
            (|| {
                let mut resp = Response::new(body("nope"));
                *resp.status_mut() = StatusCode::NOT_FOUND;
                resp
            }) as fn() -> Response<ProxyBody>,
            // Per-client state must never enter a shared cache.
            || {
                let mut resp = Response::new(body("ok"));
                resp.headers_mut()
                    .insert(SET_COOKIE, HeaderValue::from_static("sid=1"));
                resp
            },
        ] {
            let storage: SharedStorage = Arc::new(MemoryStorage::new());
            let count = Arc::new(AtomicUsize::new(0));
            let inner = counting_inner(Arc::clone(&count), make);
            for _ in 0..2 {
                let resp = service(Arc::clone(&storage), inner.clone())
                    .oneshot(request("GET", "/x"))
                    .await
                    .expect("infallible");
                let _ = resp.into_body().collect().await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert_eq!(count.load(Ordering::SeqCst), 2, "response was replayed");
        }
    }

    #[tokio::test]
    async fn oversized_bodies_stream_through_uncached() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let layer = CacheLayer::new(
            &CacheConfig {
                ttl_secs: 60,
                max_body_bytes: 4,
            },
            "users-api",
            "acme",
            Arc::clone(&storage),
        );
        let count = Arc::new(AtomicUsize::new(0));
        let inner = counting_inner(Arc::clone(&count), || {
            Response::new(body("way past the cap"))
        });
        let svc = crate::ChainService::new(layer.layer(inner));

        let resp = svc
            .oneshot(request("GET", "/big"))
            .await
            .expect("infallible");
        // The client still gets the whole body.
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(bytes.as_ref(), b"way past the cap");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            storage
                .scan_prefix("g2:acme:cache:")
                .await
                .expect("scan")
                .is_empty(),
            "oversized body cached"
        );
    }

    #[tokio::test]
    async fn storage_failure_fails_open() {
        /// A storage whose get/set always error.
        #[derive(Debug)]
        struct BrokenCache;

        #[async_trait::async_trait]
        impl Storage for BrokenCache {
            async fn get(&self, _key: &str) -> Result<Option<String>, StorageError> {
                Err(StorageError::Backend("redis is down".into()))
            }
            async fn set(
                &self,
                _key: &str,
                _value: &str,
                _ttl: Option<Duration>,
            ) -> Result<(), StorageError> {
                Err(StorageError::Backend("redis is down".into()))
            }
            async fn delete(&self, _key: &str) -> Result<bool, StorageError> {
                Ok(false)
            }
            async fn scan_prefix(&self, _prefix: &str) -> Result<Vec<String>, StorageError> {
                Ok(Vec::new())
            }
            async fn list_append(
                &self,
                _key: &str,
                _values: &[String],
                _max_len: Option<u64>,
            ) -> Result<(), StorageError> {
                Ok(())
            }
            async fn list_drain(
                &self,
                _key: &str,
                _max: usize,
            ) -> Result<Vec<String>, StorageError> {
                Ok(Vec::new())
            }
            async fn publish(&self, _channel: &str, _payload: &str) -> Result<(), StorageError> {
                Ok(())
            }
            async fn subscribe(
                &self,
                _channel: &str,
            ) -> Result<tokio::sync::mpsc::Receiver<String>, StorageError> {
                Err(StorageError::Backend("redis is down".into()))
            }
            async fn check_rate(
                &self,
                _key: &str,
                _limit: u64,
                _window: Duration,
            ) -> Result<g2_storage::LimitDecision, StorageError> {
                Err(StorageError::Backend("redis is down".into()))
            }
            async fn check_quota(
                &self,
                _key: &str,
                _max: u64,
                _period: Duration,
            ) -> Result<g2_storage::LimitDecision, StorageError> {
                Err(StorageError::Backend("redis is down".into()))
            }
        }

        let count = Arc::new(AtomicUsize::new(0));
        let inner = counting_inner(Arc::clone(&count), || Response::new(body("ok")));
        let resp = service(Arc::new(BrokenCache), inner)
            .oneshot(request("GET", "/x"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK, "cache fails open");
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(bytes.as_ref(), b"ok");
    }

    #[tokio::test]
    async fn corrupt_entry_is_treated_as_a_miss() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let count = Arc::new(AtomicUsize::new(0));
        let inner = counting_inner(Arc::clone(&count), || Response::new(body("fresh")));

        // Poison the exact key the layer will compute.
        let key = format!(
            "{}{}",
            response_cache_key_prefix("acme", "users-api"),
            hash_key("GET /x")
        );
        storage
            .set(&key, "not json", None)
            .await
            .expect("seed poison");

        let resp = service(Arc::clone(&storage), inner)
            .oneshot(request("GET", "/x"))
            .await
            .expect("infallible");
        assert_eq!(count.load(Ordering::SeqCst), 1, "fell through to upstream");
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(bytes.as_ref(), b"fresh");

        // The rewrite self-heals the poisoned entry.
        await_entry(&storage).await;
        for _ in 0..100 {
            if decode_entry(&storage.get(&key).await.expect("get").expect("set")).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("poisoned entry never overwritten");
    }

    #[tokio::test]
    async fn entries_expire_with_the_configured_ttl() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let layer = CacheLayer::new(
            &CacheConfig {
                ttl_secs: 1,
                max_body_bytes: 1024,
            },
            "users-api",
            "acme",
            Arc::clone(&storage),
        );
        let count = Arc::new(AtomicUsize::new(0));
        let inner = counting_inner(Arc::clone(&count), || Response::new(body("ok")));
        let svc = |inner| crate::ChainService::new(layer.layer(inner));

        let _ = svc(inner.clone())
            .oneshot(request("GET", "/x"))
            .await
            .expect("infallible")
            .into_body()
            .collect()
            .await;
        await_entry(&storage).await;

        // MemoryStorage TTLs run on tokio time; jump past the expiry.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::time::resume();

        let resp = svc(inner)
            .oneshot(request("GET", "/x"))
            .await
            .expect("infallible");
        assert!(
            !resp.headers().contains_key(CACHE_STATUS_HEADER),
            "expired entry served"
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn entry_encoding_round_trips() {
        let stored = encode_entry(
            StatusCode::CREATED,
            &[(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/json"),
            )],
            br#"{"ok":true}"#,
        );
        let resp = decode_entry(&stored).expect("decodes");
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            resp.headers().get("content-type").expect("ct").as_bytes(),
            b"application/json"
        );
        assert_eq!(
            resp.headers()
                .get(CACHE_STATUS_HEADER)
                .expect("marker")
                .as_bytes(),
            b"hit"
        );

        assert!(decode_entry("not json").is_none());
        assert!(decode_entry(r#"{"status":9,"headers":[],"body_b64":""}"#).is_none());
    }
}
