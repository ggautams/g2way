//! GraphQL-aware response caching (ADR-0012), driven by the GraphQL layer.
//!
//! The HTTP response cache ([`crate::cache`], chain slot 18) never helps
//! GraphQL traffic: it only caches safe methods (GraphQL rides `POST`), and
//! in gateway-executed modes (udg/supergraph) the GraphQL layer answers
//! before slot 18 ever runs. This module gives [`crate::graphql`] its own
//! cache keyed on what actually identifies a GraphQL response — the active
//! schema, the operation name, the query text, and the variables — sharing
//! the storage entry shape, the recording-body tee, and the fail-open
//! stance of the HTTP cache.
//!
//! What differs from the HTTP cache, and why:
//!
//! - Entries live under `g2:{org}:cache:{scope}:graphql:` — disjoint from
//!   the HTTP cache's `{scope}` prefix, and still a plain prefix scan for a
//!   future flush-by-API operation.
//! - Only **query** operations are cached; mutations and subscriptions
//!   bypass, and a mutation does not invalidate anything — like the HTTP
//!   cache, the TTL is the whole contract.
//! - A response whose JSON carries a non-empty top-level `errors` array is
//!   never stored ([`WritePolicy::GraphQlSuccess`]): a transient upstream
//!   failure inside a `200` must not be replayed for the whole TTL.
//! - The key starts with a digest of the active SDL, so a schema swap
//!   (sync or reload) starts a fresh keyspace; superseded entries age out.
//!
//! The cache is shared across clients like the HTTP cache: per-key grants
//! are enforced by the GraphQL layer **before** every lookup, so a client
//! can never read a cached entry for a query it is not allowed to make.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use g2_core::api_definition::response_cache_key_prefix;
use g2_core::session::hash_key;
use g2_core::CacheConfig;
use http::header::SET_COOKIE;
use http::Response;

use crate::cache::{decode_entry, CacheWrite, RecordingBody, WritePolicy};
use crate::graphql::RawVariables;
use crate::ProxyBody;

/// One API's GraphQL response cache, precomputed at route-build time.
pub(crate) struct GraphQlCache {
    /// `g2:{org}:cache:{scope}:graphql:` — the operation digest is appended
    /// per request.
    key_prefix: String,
    ttl: Duration,
    max_body_bytes: usize,
    storage: g2_storage::SharedStorage,
}

impl std::fmt::Debug for GraphQlCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphQlCache")
            .field("key_prefix", &self.key_prefix)
            .field("ttl", &self.ttl)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

impl GraphQlCache {
    /// Builds the cache for one scope (the API id, or `{api_id}:{version}`
    /// for one version of a versioned API — same scoping as the HTTP
    /// cache).
    pub(crate) fn new(
        config: &CacheConfig,
        scope: &str,
        org_id: &str,
        storage: g2_storage::SharedStorage,
    ) -> Self {
        Self {
            key_prefix: response_cache_key_prefix(org_id, &format!("{scope}:graphql")),
            ttl: Duration::from_secs(config.ttl_secs),
            max_body_bytes: usize::try_from(config.max_body_bytes).unwrap_or(usize::MAX),
            storage,
        }
    }

    /// The storage key for one operation: the prefix plus a digest of the
    /// active schema, the operation name, the query text, and the
    /// canonical variables (see [`canonical_variables`]).
    pub(crate) fn key(
        &self,
        sdl_hash: &str,
        operation_name: Option<&str>,
        query: &str,
        variables: &str,
    ) -> String {
        let name = operation_name.unwrap_or("");
        format!(
            "{}{}",
            self.key_prefix,
            hash_key(&format!("{sdl_hash}\n{name}\n{query}\n{variables}"))
        )
    }

    /// Fail-open lookup: a storage error or a corrupt entry is a miss.
    pub(crate) async fn lookup(&self, key: &str) -> Option<Response<ProxyBody>> {
        match self.storage.get(key).await {
            Ok(Some(stored)) => {
                let resp = decode_entry(&stored);
                if resp.is_none() {
                    // A corrupt entry is a miss; the fresh response
                    // overwrites it.
                    tracing::warn!(key = %key, "corrupt cache entry ignored");
                }
                resp
            }
            Ok(None) => None,
            Err(e) => {
                tracing::error!(key = %key, error = %e, "cache lookup failed; failing open");
                None
            }
        }
    }

    /// Wraps a cacheable response's body in the recording tee; anything not
    /// worth caching (non-`2xx`, or per-client state via `Set-Cookie`) is
    /// returned untouched. The tee's background write additionally drops
    /// any body that is not a GraphQL success
    /// ([`WritePolicy::GraphQlSuccess`]).
    pub(crate) fn record(&self, resp: Response<ProxyBody>, key: String) -> Response<ProxyBody> {
        if !resp.status().is_success() || resp.headers().contains_key(SET_COOKIE) {
            return resp;
        }
        let (parts, body) = resp.into_parts();
        let write = CacheWrite {
            storage: Arc::clone(&self.storage),
            key,
            ttl: self.ttl,
            status: parts.status,
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            policy: WritePolicy::GraphQlSuccess,
        };
        let recording = RecordingBody {
            inner: body,
            buf: BytesMut::new(),
            max: self.max_body_bytes,
            write: Some(write),
        };
        Response::from_parts(parts, ProxyBody::new(recording))
    }
}

/// The canonical form of a request's variables for the cache key.
///
/// Pre-parsed variables (a `POST` envelope) re-serialize through
/// [`serde_json::Value`], whose object maps are ordered by key — so
/// `{"a":1,"b":2}` and `{"b":2,"a":1}` share an entry. `GET` `?variables=`
/// text is parsed the same way when it is valid JSON and hashed verbatim
/// otherwise (a spurious miss, never a leak — the upstream rejects it
/// anyway). Absent, `null`, and empty variables all canonicalize to `""`.
pub(crate) fn canonical_variables(raw: Option<&RawVariables>) -> String {
    let canonical = match raw {
        None => return String::new(),
        Some(RawVariables::Parsed(value)) => serde_json::to_value(value)
            .expect("JSON value round-trips through serde_json: no fallible types")
            .to_string(),
        Some(RawVariables::Text(text)) => match serde_json::from_str::<serde_json::Value>(text) {
            Ok(value) => value.to_string(),
            Err(_) => text.clone(),
        },
    };
    if canonical == "null" || canonical == "{}" {
        return String::new();
    }
    canonical
}

/// [`canonical_variables`] for a persisted endpoint's already-substituted
/// [`serde_json::Value`] (its maps are key-ordered, so `to_string` is
/// canonical as-is).
pub(crate) fn canonical_json_variables(value: Option<&serde_json::Value>) -> String {
    match value {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(value) => {
            let canonical = value.to_string();
            if canonical == "{}" {
                String::new()
            } else {
                canonical
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use g2_storage::{MemoryStorage, SharedStorage, Storage, StorageError};
    use http::StatusCode;
    use http_body_util::BodyExt;

    use super::*;
    use crate::cache::CACHE_STATUS_HEADER;

    fn cache(storage: SharedStorage) -> GraphQlCache {
        let config: CacheConfig = serde_json::from_str("{}").expect("defaults");
        GraphQlCache::new(&config, "gql-api", "acme", storage)
    }

    fn parsed(json: &str) -> RawVariables {
        RawVariables::Parsed(serde_json::from_str(json).expect("valid JSON"))
    }

    #[test]
    fn keys_scope_and_vary_on_every_component() {
        let c = cache(Arc::new(MemoryStorage::new()));
        let base = c.key("sdl1", Some("Op"), "query Op { hello }", "");
        assert!(
            base.starts_with("g2:acme:cache:gql-api:graphql:"),
            "got: {base}"
        );
        assert_eq!(base, c.key("sdl1", Some("Op"), "query Op { hello }", ""));
        for other in [
            c.key("sdl2", Some("Op"), "query Op { hello }", ""),
            c.key("sdl1", None, "query Op { hello }", ""),
            c.key("sdl1", Some("Op"), "query Op { hi }", ""),
            c.key("sdl1", Some("Op"), "query Op { hello }", r#"{"a":1}"#),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn variables_canonicalize_by_key_order_and_emptiness() {
        assert_eq!(canonical_variables(None), "");
        assert_eq!(canonical_variables(Some(&parsed("null"))), "");
        assert_eq!(canonical_variables(Some(&parsed("{}"))), "");
        assert_eq!(
            canonical_variables(Some(&RawVariables::Text("null".into()))),
            ""
        );
        assert_eq!(
            canonical_variables(Some(&parsed(r#"{"b":2,"a":1}"#))),
            canonical_variables(Some(&parsed(r#"{"a":1,"b":2}"#))),
        );
        assert_eq!(
            canonical_variables(Some(&RawVariables::Text(r#"{"b":2,"a":1}"#.into()))),
            canonical_variables(Some(&parsed(r#"{"a":1,"b":2}"#))),
        );
        // Unparseable GET text hashes verbatim rather than erroring.
        assert_eq!(
            canonical_variables(Some(&RawVariables::Text("not json".into()))),
            "not json"
        );
    }

    fn ok_json(body: &'static str) -> Response<ProxyBody> {
        Response::new(ProxyBody::new(http_body_util::Full::new(
            bytes::Bytes::from_static(body.as_bytes()),
        )))
    }

    async fn drive(resp: Response<ProxyBody>) -> bytes::Bytes {
        resp.into_body().collect().await.expect("body").to_bytes()
    }

    async fn entry_count(storage: &SharedStorage) -> usize {
        // Bounded wait: writes land from a background task.
        for _ in 0..100 {
            let keys = storage.scan_prefix("g2:acme:cache:").await.expect("scan");
            if !keys.is_empty() {
                return keys.len();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        0
    }

    #[tokio::test]
    async fn recorded_success_round_trips_as_a_hit() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let c = cache(Arc::clone(&storage));
        let key = c.key("sdl", None, "{ hello }", "");

        assert!(c.lookup(&key).await.is_none(), "cold cache");
        let resp = c.record(ok_json(r#"{"data":{"hello":"hi"}}"#), key.clone());
        assert_eq!(drive(resp).await.as_ref(), br#"{"data":{"hello":"hi"}}"#);
        assert_eq!(entry_count(&storage).await, 1);

        let hit = c.lookup(&key).await.expect("hit");
        assert_eq!(
            hit.headers()
                .get(CACHE_STATUS_HEADER)
                .expect("marker")
                .as_bytes(),
            b"hit"
        );
        assert_eq!(drive(hit).await.as_ref(), br#"{"data":{"hello":"hi"}}"#);
    }

    #[tokio::test]
    async fn error_responses_and_per_client_state_are_never_stored() {
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let c = cache(Arc::clone(&storage));

        // GraphQL errors inside a 200: dropped by the write policy.
        let resp = c.record(
            ok_json(r#"{"errors":[{"message":"boom"}]}"#),
            c.key("sdl", None, "{ a }", ""),
        );
        drive(resp).await;

        // Set-Cookie: never even teed.
        let mut cookie = ok_json(r#"{"data":1}"#);
        cookie
            .headers_mut()
            .insert(SET_COOKIE, http::HeaderValue::from_static("sid=1"));
        drive(c.record(cookie, c.key("sdl", None, "{ b }", ""))).await;

        // Non-2xx: never teed either.
        let mut bad = ok_json(r#"{"data":1}"#);
        *bad.status_mut() = StatusCode::BAD_GATEWAY;
        drive(c.record(bad, c.key("sdl", None, "{ c }", ""))).await;

        // Give any stray background write a chance to land, then assert.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let keys = storage.scan_prefix("g2:acme:cache:").await.expect("scan");
        assert!(keys.is_empty(), "nothing cached, got: {keys:?}");
    }

    #[tokio::test]
    async fn storage_failure_fails_open_and_corrupt_entries_are_misses() {
        struct BrokenStorage;

        #[async_trait::async_trait]
        impl Storage for BrokenStorage {
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

        let broken = cache(Arc::new(BrokenStorage));
        assert!(
            broken
                .lookup(&broken.key("s", None, "{ a }", ""))
                .await
                .is_none(),
            "storage error is a miss"
        );

        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let c = cache(Arc::clone(&storage));
        let key = c.key("sdl", None, "{ a }", "");
        storage
            .set(&key, "not a cache entry", None)
            .await
            .expect("seed");
        assert!(c.lookup(&key).await.is_none(), "corrupt entry is a miss");
    }
}
