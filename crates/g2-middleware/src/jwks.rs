//! JWKS (RFC 7517) key fetching and caching for JWT and OIDC auth.
//!
//! An API configured with `auth.jwks_url` verifies RS256 tokens against keys
//! fetched from that URL instead of a static PEM. Keys live in a pod-local
//! `kid → DecodingKey` map behind an [`ArcSwap`], read lock-free on the hot
//! path (ADR-0001) and replaced wholesale by refreshes.
//!
//! The OIDC mode reuses the same cache but usually knows only the issuer:
//! `JwksCache::via_discovery` resolves the JWKS URL lazily on the first
//! refresh by fetching `{issuer}/.well-known/openid-configuration`,
//! requiring the document's `issuer` to match the configured one exactly,
//! and pins the resolved `jwks_uri` for the route's lifetime (a config
//! reload rebuilds the route and re-discovers).
//!
//! Refresh happens two ways:
//!
//! - **Periodically**: `JwksCache::spawn_refresher` starts a background
//!   task (same lifecycle as the upstream health checker: it holds a `Weak`
//!   reference and self-exits once a config reload drops the route that owns
//!   the cache — no abort plumbing).
//! - **On miss**: a token with an unknown `kid` triggers one immediate
//!   refetch, rate-limited by a cooldown (`MISS_REFETCH_COOLDOWN_SECS`) so a
//!   flood of garbage kids cannot hammer the identity provider.
//!
//! Failed refreshes log a warning and keep the previous key set
//! (stale-on-error); a *successful* fetch is authoritative even when it
//! shrinks or empties the set — that is how key revocation propagates.
//!
//! The actual HTTP GET is abstracted behind [`JwksFetch`], implemented by the
//! proxy crate over its shared upstream client: g2-middleware itself carries
//! no HTTP client or TLS stack (the same inversion as
//! [`SharedStorage`](g2_storage::SharedStorage)).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::DecodingKey;

use crate::auth::unix_now_secs;

/// Boxed future returned by [`JwksFetch::fetch`].
pub type JwksFetchFuture =
    Pin<Box<dyn Future<Output = Result<bytes::Bytes, String>> + Send + 'static>>;

/// Fetches the raw bytes of a JWKS document.
///
/// Implemented by the proxy crate over its shared upstream HTTPS client;
/// tests substitute in-memory fakes. Errors are plain strings — the caller
/// only ever logs them.
pub trait JwksFetch: Send + Sync + 'static {
    /// `GET`s `url`, returning the response body on a 2xx status.
    fn fetch(&self, url: &str) -> JwksFetchFuture;
}

/// Shared fetcher handle threaded into
/// [`AuthLayer::from_config`](crate::AuthLayer::from_config).
pub type SharedJwksFetch = Arc<dyn JwksFetch>;

/// Minimum seconds between fetches triggered by unknown-`kid` cache misses.
pub(crate) const MISS_REFETCH_COOLDOWN_SECS: u64 = 10;

/// Where the key set is fetched from.
enum JwksEndpoint {
    /// A JWKS URL known at config time.
    Url(String),
    /// An OIDC issuer whose JWKS URL is resolved from the discovery
    /// document on the first successful refresh, then pinned.
    Discovery {
        issuer_url: String,
        resolved: std::sync::OnceLock<String>,
    },
}

/// The two fields of an OIDC discovery document the gateway reads.
#[derive(serde::Deserialize)]
struct DiscoveryDoc {
    issuer: String,
    jwks_uri: String,
}

/// Pod-local `kid → DecodingKey` cache for one API's JWKS endpoint.
pub(crate) struct JwksCache {
    api_id: Arc<str>,
    endpoint: JwksEndpoint,
    fetcher: SharedJwksFetch,
    /// Current key set; starts empty until the first successful fetch.
    keys: ArcSwap<HashMap<String, DecodingKey>>,
    /// Unix seconds of the last fetch attempt — the on-miss cooldown gate.
    last_attempt_secs: AtomicU64,
}

impl JwksCache {
    /// A cache for `url`, initially empty.
    pub(crate) fn new(api_id: &str, url: String, fetcher: SharedJwksFetch) -> Self {
        Self::with_endpoint(api_id, JwksEndpoint::Url(url), fetcher)
    }

    /// A cache that discovers its JWKS URL from `issuer_url`'s OIDC
    /// discovery document, initially empty.
    pub(crate) fn via_discovery(
        api_id: &str,
        issuer_url: String,
        fetcher: SharedJwksFetch,
    ) -> Self {
        Self::with_endpoint(
            api_id,
            JwksEndpoint::Discovery {
                issuer_url,
                resolved: std::sync::OnceLock::new(),
            },
            fetcher,
        )
    }

    fn with_endpoint(api_id: &str, endpoint: JwksEndpoint, fetcher: SharedJwksFetch) -> Self {
        Self {
            api_id: api_id.into(),
            endpoint,
            fetcher,
            keys: ArcSwap::from_pointee(HashMap::new()),
            last_attempt_secs: AtomicU64::new(0),
        }
    }

    /// The endpoint as it is best known right now, for log lines: the JWKS
    /// URL, or the issuer while discovery has not resolved one yet.
    fn endpoint_desc(&self) -> &str {
        match &self.endpoint {
            JwksEndpoint::Url(url) => url,
            JwksEndpoint::Discovery {
                issuer_url,
                resolved,
            } => resolved.get().map_or(issuer_url.as_str(), String::as_str),
        }
    }

    /// Resolves the JWKS URL, running OIDC discovery on first use.
    ///
    /// The resolved URI is pinned for the cache's lifetime — identity
    /// providers do not move it, and a config reload rebuilds the route
    /// (and this cache) anyway. Discovery failures leave it unresolved so
    /// the next refresh retries.
    async fn jwks_url(&self) -> Result<String, String> {
        let JwksEndpoint::Discovery {
            issuer_url,
            resolved,
        } = &self.endpoint
        else {
            let JwksEndpoint::Url(url) = &self.endpoint else {
                unreachable!("endpoint is either Url or Discovery");
            };
            return Ok(url.clone());
        };
        if let Some(url) = resolved.get() {
            return Ok(url.clone());
        }
        // OIDC Discovery §4: the well-known path is appended to the issuer
        // (one trailing slash trimmed); the `iss` claim match elsewhere
        // stays byte-exact.
        let base = issuer_url.strip_suffix('/').unwrap_or(issuer_url);
        let discovery_url = format!("{base}/.well-known/openid-configuration");
        let body = self.fetcher.fetch(&discovery_url).await?;
        let doc: DiscoveryDoc = serde_json::from_slice(&body)
            .map_err(|e| format!("response is not a valid OIDC discovery document: {e}"))?;
        if doc.issuer != *issuer_url {
            return Err(format!(
                "discovery document issuer `{}` does not match configured issuer `{issuer_url}`",
                doc.issuer
            ));
        }
        // A concurrent refresh may have resolved it first; both read the
        // same provider, so first write wins.
        let _ = resolved.set(doc.jwks_uri);
        Ok(resolved
            .get()
            .cloned()
            .expect("a OnceLock that was just set is non-empty"))
    }

    /// Fetches and swaps in the key set, returning how many keys it holds.
    ///
    /// Keeps only RSA keys that carry a `kid` and whose `alg`, if present, is
    /// RS256; anything else is skipped with a debug log. On fetch or parse
    /// failure the previous set stays in place (stale-on-error) and the error
    /// is returned for the caller to log.
    pub(crate) async fn refresh(&self) -> Result<usize, String> {
        self.last_attempt_secs
            .store(unix_now_secs(), Ordering::Relaxed);
        let url = self.jwks_url().await?;
        let body = self.fetcher.fetch(&url).await?;
        let set: JwkSet = serde_json::from_slice(&body)
            .map_err(|e| format!("response is not a valid JWKS document: {e}"))?;

        let mut map = HashMap::new();
        for jwk in &set.keys {
            let Some(kid) = jwk.common.key_id.as_deref() else {
                tracing::debug!(api_id = %self.api_id, "skipping JWKS key without a kid");
                continue;
            };
            if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_)) {
                tracing::debug!(api_id = %self.api_id, kid, "skipping non-RSA JWKS key");
                continue;
            }
            if jwk
                .common
                .key_algorithm
                .is_some_and(|alg| alg != jsonwebtoken::jwk::KeyAlgorithm::RS256)
            {
                tracing::debug!(api_id = %self.api_id, kid, "skipping non-RS256 JWKS key");
                continue;
            }
            match DecodingKey::from_jwk(jwk) {
                Ok(key) => {
                    map.insert(kid.to_owned(), key);
                }
                Err(e) => {
                    tracing::debug!(api_id = %self.api_id, kid, error = %e, "unusable JWKS key");
                }
            }
        }
        let count = map.len();
        self.keys.store(Arc::new(map));
        Ok(count)
    }

    /// Resolves `kid`, refetching the set once (cooldown-gated) on a miss.
    ///
    /// Concurrent misses elect a single fetcher via compare-exchange on the
    /// attempt timestamp; losers and cooled-down callers just answer from the
    /// current map.
    pub(crate) async fn key_for(&self, kid: &str) -> Option<DecodingKey> {
        if let Some(key) = self.keys.load().get(kid) {
            return Some(key.clone());
        }
        let last = self.last_attempt_secs.load(Ordering::Relaxed);
        let now = unix_now_secs();
        let won_refetch = now.saturating_sub(last) >= MISS_REFETCH_COOLDOWN_SECS
            && self
                .last_attempt_secs
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok();
        if won_refetch {
            if let Err(e) = self.refresh().await {
                tracing::warn!(
                    api_id = %self.api_id,
                    url = %self.endpoint_desc(),
                    error = %e,
                    "JWKS refetch after unknown kid failed"
                );
            }
        }
        self.keys.load().get(kid).cloned()
    }

    /// Spawns the periodic refresh loop for `cache`.
    ///
    /// Returns the task handle, or `None` when no tokio runtime is running
    /// (synchronous route builds in tests — the binary always builds tables
    /// inside the runtime). The first refresh runs immediately; the task
    /// holds only a [`Weak`] reference and exits once the owning route is
    /// dropped by a config reload.
    pub(crate) fn spawn_refresher(
        cache: &Arc<Self>,
        interval: Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                api_id = %cache.api_id,
                "no tokio runtime available; JWKS background refresh stays disabled"
            );
            return None;
        };
        let weak = Arc::downgrade(cache);
        Some(handle.spawn(async move {
            refresh_once(&weak).await;
            loop {
                tokio::time::sleep(interval).await;
                if !refresh_once(&weak).await {
                    return;
                }
            }
        }))
    }

    fn debug_key_count(&self) -> usize {
        self.keys.load().len()
    }

    /// Clears the on-miss cooldown so a test can force the next miss to
    /// refetch without waiting [`MISS_REFETCH_COOLDOWN_SECS`] of wall time.
    #[cfg(test)]
    pub(crate) fn reset_miss_cooldown(&self) {
        self.last_attempt_secs.store(0, Ordering::Relaxed);
    }
}

/// One refresh tick; returns `false` once the cache has been dropped.
async fn refresh_once(weak: &Weak<JwksCache>) -> bool {
    let Some(cache) = weak.upgrade() else {
        return false;
    };
    match cache.refresh().await {
        Ok(count) => {
            tracing::debug!(api_id = %cache.api_id, keys = count, "JWKS refreshed");
        }
        Err(e) => {
            tracing::warn!(
                api_id = %cache.api_id,
                url = %cache.endpoint_desc(),
                error = %e,
                "JWKS refresh failed; keeping previous keys"
            );
        }
    }
    true
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("api_id", &self.api_id)
            .field("url", &self.endpoint_desc())
            .field("keys", &self.debug_key_count())
            .finish_non_exhaustive() // key material and fetcher stay unprintable
    }
}

/// Test-only fakes shared with the auth-layer tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    /// Programmable in-memory fetcher: serves the current payload (or a
    /// per-URL route when one is set) and counts calls, in total and per
    /// URL.
    pub(crate) struct FakeFetch {
        body: Mutex<Result<bytes::Bytes, String>>,
        routes: Mutex<HashMap<String, Result<bytes::Bytes, String>>>,
        calls: AtomicUsize,
        calls_by_url: Mutex<HashMap<String, usize>>,
    }

    impl FakeFetch {
        pub(crate) fn new(body: Result<&str, &str>) -> Arc<Self> {
            let fake = Self {
                body: Mutex::new(Err(String::new())),
                routes: Mutex::new(HashMap::new()),
                calls: AtomicUsize::new(0),
                calls_by_url: Mutex::new(HashMap::new()),
            };
            fake.set_body(body);
            Arc::new(fake)
        }

        pub(crate) fn set_body(&self, body: Result<&str, &str>) {
            *self.body.lock().unwrap() = body
                .map(|b| bytes::Bytes::from(b.to_owned()))
                .map_err(str::to_owned);
        }

        /// Serves `body` for requests to exactly `url` (other URLs keep
        /// getting the default body).
        pub(crate) fn set_route(&self, url: &str, body: Result<&str, &str>) {
            self.routes.lock().unwrap().insert(
                url.to_owned(),
                body.map(|b| bytes::Bytes::from(b.to_owned()))
                    .map_err(str::to_owned),
            );
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }

        /// How many times exactly `url` was fetched.
        pub(crate) fn calls_to(&self, url: &str) -> usize {
            self.calls_by_url
                .lock()
                .unwrap()
                .get(url)
                .copied()
                .unwrap_or(0)
        }
    }

    impl JwksFetch for FakeFetch {
        fn fetch(&self, url: &str) -> JwksFetchFuture {
            self.calls.fetch_add(1, Ordering::Relaxed);
            *self
                .calls_by_url
                .lock()
                .unwrap()
                .entry(url.to_owned())
                .or_insert(0) += 1;
            let body = self
                .routes
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .unwrap_or_else(|| self.body.lock().unwrap().clone());
            Box::pin(async move { body })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeFetch;
    use super::*;

    fn cache_with(fetch: &Arc<FakeFetch>) -> JwksCache {
        JwksCache::new(
            "api",
            "http://idp.internal/jwks.json".into(),
            Arc::clone(fetch) as SharedJwksFetch,
        )
    }

    /// A 2048-bit RSA JWK (`n`/`e` are structurally valid base64url); good
    /// enough to exercise parsing and map handling without real signatures —
    /// signature-level tests live in `auth::tests::jwt`.
    fn jwks_json(kid: &str) -> String {
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{n}","e":"AQAB"}}]}}"#
        )
    }

    #[tokio::test]
    async fn refresh_parses_and_swaps_the_key_set() {
        let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
        let cache = cache_with(&fetch);
        assert_eq!(cache.refresh().await.expect("refresh works"), 1);
        assert!(cache.key_for("k1").await.is_some());
    }

    #[tokio::test]
    async fn refresh_skips_unusable_keys() {
        // No kid, wrong alg, and a non-RSA key type: all skipped.
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let body = format!(
            r#"{{"keys":[
                {{"kty":"RSA","n":"{n}","e":"AQAB"}},
                {{"kty":"RSA","kid":"wrong-alg","alg":"RS512","n":"{n}","e":"AQAB"}},
                {{"kty":"oct","kid":"symmetric","k":"c2VjcmV0"}},
                {{"kty":"RSA","kid":"good","n":"{n}","e":"AQAB"}}
            ]}}"#
        );
        let fetch = FakeFetch::new(Ok(&body));
        let cache = cache_with(&fetch);
        assert_eq!(cache.refresh().await.expect("refresh works"), 1);
        assert!(cache.key_for("good").await.is_some());
    }

    #[tokio::test]
    async fn failed_refresh_keeps_the_previous_keys() {
        let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
        let cache = cache_with(&fetch);
        cache.refresh().await.expect("first refresh works");

        fetch.set_body(Err("boom"));
        assert!(cache.refresh().await.is_err());
        assert!(
            cache.key_for("k1").await.is_some(),
            "stale keys survive a failed refresh"
        );

        fetch.set_body(Ok("{not json"));
        assert!(cache.refresh().await.is_err());
        assert!(cache.key_for("k1").await.is_some());
    }

    #[tokio::test]
    async fn successful_empty_set_is_authoritative() {
        let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
        let cache = cache_with(&fetch);
        cache.refresh().await.expect("first refresh works");

        fetch.set_body(Ok(r#"{"keys":[]}"#));
        assert_eq!(cache.refresh().await.expect("empty set is valid"), 0);
        assert!(
            cache.key_for("k1").await.is_none(),
            "revoked keys disappear on the next successful fetch"
        );
    }

    #[tokio::test]
    async fn unknown_kid_refetches_once_within_the_cooldown() {
        let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
        let cache = cache_with(&fetch);

        // Cold cache + unknown kid: the miss itself triggers the fetch
        // (last_attempt starts at 0, so the first miss always refetches).
        assert!(cache.key_for("nope").await.is_none());
        assert_eq!(fetch.calls(), 1);

        // Further misses inside the cooldown answer from the map only.
        assert!(cache.key_for("nope").await.is_none());
        assert!(cache.key_for("also-nope").await.is_none());
        assert_eq!(fetch.calls(), 1, "cooldown holds");

        // A known kid was loaded by that first fetch.
        assert!(cache.key_for("k1").await.is_some());
        assert_eq!(fetch.calls(), 1);
    }

    #[tokio::test]
    async fn spawned_refresher_exits_when_the_cache_is_dropped() {
        let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
        let cache = Arc::new(cache_with(&fetch));
        let handle = JwksCache::spawn_refresher(&cache, Duration::from_millis(10))
            .expect("runtime is available");

        // The eager first refresh lands without waiting for a tick.
        tokio::time::timeout(Duration::from_secs(2), async {
            while cache.key_for("k1").await.is_none() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("first refresh happens promptly");

        drop(cache);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task exits once the cache is dropped")
            .expect("task does not panic");
    }

    const ISSUER: &str = "http://idp.internal/realm";
    const DISCOVERY_URL: &str = "http://idp.internal/realm/.well-known/openid-configuration";
    const KEYS_URL: &str = "http://idp.internal/realm/keys";

    fn discovery_doc(issuer: &str) -> String {
        format!(r#"{{"issuer":"{issuer}","jwks_uri":"{KEYS_URL}"}}"#)
    }

    fn discovery_cache(fetch: &Arc<FakeFetch>) -> JwksCache {
        JwksCache::via_discovery("api", ISSUER.into(), Arc::clone(fetch) as SharedJwksFetch)
    }

    #[tokio::test]
    async fn discovery_resolves_jwks_uri_once_then_loads_keys() {
        let fetch = FakeFetch::new(Err("unrouted URL"));
        fetch.set_route(DISCOVERY_URL, Ok(&discovery_doc(ISSUER)));
        fetch.set_route(KEYS_URL, Ok(&jwks_json("k1")));
        let cache = discovery_cache(&fetch);

        assert_eq!(cache.refresh().await.expect("refresh works"), 1);
        assert!(cache.key_for("k1").await.is_some());
        assert_eq!(fetch.calls_to(DISCOVERY_URL), 1);
        assert_eq!(fetch.calls_to(KEYS_URL), 1);

        // The jwks_uri is pinned: later refreshes skip discovery.
        cache.refresh().await.expect("second refresh works");
        assert_eq!(fetch.calls_to(DISCOVERY_URL), 1, "discovery is pinned");
        assert_eq!(fetch.calls_to(KEYS_URL), 2);
    }

    #[tokio::test]
    async fn discovery_trims_one_trailing_slash_for_the_wellknown_url() {
        // Configured issuer ends in `/`; the discovery URL must not get a
        // double slash, but the issuer match stays byte-exact.
        let issuer = format!("{ISSUER}/");
        let fetch = FakeFetch::new(Err("unrouted URL"));
        fetch.set_route(DISCOVERY_URL, Ok(&discovery_doc(&issuer)));
        fetch.set_route(KEYS_URL, Ok(&jwks_json("k1")));
        let cache = JwksCache::via_discovery("api", issuer, Arc::clone(&fetch) as SharedJwksFetch);

        assert_eq!(cache.refresh().await.expect("refresh works"), 1);
        assert_eq!(fetch.calls_to(DISCOVERY_URL), 1);
    }

    #[tokio::test]
    async fn discovery_issuer_mismatch_is_an_error() {
        let fetch = FakeFetch::new(Err("unrouted URL"));
        fetch.set_route(DISCOVERY_URL, Ok(&discovery_doc("http://evil.example")));
        fetch.set_route(KEYS_URL, Ok(&jwks_json("k1")));
        let cache = discovery_cache(&fetch);

        assert!(cache.refresh().await.is_err());
        assert!(cache.key_for("k1").await.is_none(), "no keys were loaded");
        assert_eq!(fetch.calls_to(KEYS_URL), 0, "jwks_uri is never trusted");
    }

    #[tokio::test]
    async fn discovery_failure_is_retried_on_the_next_refresh() {
        let fetch = FakeFetch::new(Err("unrouted URL"));
        fetch.set_route(DISCOVERY_URL, Err("IdP down"));
        fetch.set_route(KEYS_URL, Ok(&jwks_json("k1")));
        let cache = discovery_cache(&fetch);

        assert!(cache.refresh().await.is_err());
        // The IdP comes back: the unresolved endpoint retries discovery.
        fetch.set_route(DISCOVERY_URL, Ok(&discovery_doc(ISSUER)));
        assert_eq!(cache.refresh().await.expect("refresh works"), 1);
        assert_eq!(fetch.calls_to(DISCOVERY_URL), 2);
    }

    #[tokio::test]
    async fn malformed_discovery_document_is_an_error() {
        let fetch = FakeFetch::new(Err("unrouted URL"));
        fetch.set_route(DISCOVERY_URL, Ok(r#"{"issuer": 42}"#));
        let cache = discovery_cache(&fetch);
        assert!(cache.refresh().await.is_err());
    }

    #[test]
    fn debug_prints_no_key_material() {
        let fetch = FakeFetch::new(Ok(&jwks_json("k1")));
        let cache = cache_with(&fetch);
        let debug = format!("{cache:?}");
        assert!(debug.contains("api_id"));
        assert!(!debug.contains("AQAB"));
    }
}
