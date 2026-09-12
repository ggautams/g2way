//! Redis-backed [`Storage`] implementation for multi-pod deployments.

use std::time::Duration;

// `::redis` disambiguates the extern crate from this module (also `redis`).
use ::redis::aio::ConnectionManager;

use crate::{Storage, StorageError};

fn backend_err(e: ::redis::RedisError) -> StorageError {
    StorageError::Backend(e.to_string())
}

/// A [`Storage`] backed by a shared Redis instance.
///
/// This is the production backend: every gateway pod points at the same
/// Redis, so keys, rate-limit counters, and quota counters are shared
/// cluster-wide. Values expire server-side via `PX`, so TTL semantics match
/// [`crate::MemoryStorage`] without any gateway-side sweeping.
///
/// Internally this wraps a [`ConnectionManager`]: a single multiplexed
/// connection that transparently reconnects (with backoff) after network
/// failures. Cloning is cheap and clones share the connection, so one
/// `RedisStorage` is created at startup and cloned wherever needed.
pub struct RedisStorage {
    conn: ConnectionManager,
}

impl Clone for RedisStorage {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
        }
    }
}

impl std::fmt::Debug for RedisStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // ConnectionManager holds no printable state worth exposing.
        f.debug_struct("RedisStorage").finish_non_exhaustive()
    }
}

impl RedisStorage {
    /// Connects to Redis at `url` (for example `redis://127.0.0.1:6379/`).
    ///
    /// The initial connection is verified eagerly so a bad address fails at
    /// startup rather than on the first request.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] when the URL cannot be parsed or the
    /// server cannot be reached.
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let client = redis::Client::open(url).map_err(backend_err)?;
        let conn = client.get_connection_manager().await.map_err(backend_err)?;
        Ok(Self { conn })
    }
}

#[async_trait::async_trait]
impl Storage for RedisStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        redis::cmd("GET")
            .arg(key)
            .query_async(&mut self.conn.clone())
            .await
            .map_err(backend_err)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StorageError> {
        let mut cmd = redis::cmd("SET");
        cmd.arg(key).arg(value);
        if let Some(ttl) = ttl {
            // PX rejects 0, and as_millis truncates: round sub-millisecond
            // TTLs up to 1ms rather than erroring.
            let millis = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1);
            cmd.arg("PX").arg(millis);
        }
        cmd.query_async::<()>(&mut self.conn.clone())
            .await
            .map_err(backend_err)
    }

    async fn delete(&self, key: &str) -> Result<bool, StorageError> {
        let removed: u64 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut self.conn.clone())
            .await
            .map_err(backend_err)?;
        Ok(removed > 0)
    }
}

// Integration tests against a real Redis. All #[ignore]d: `make redis-up`
// provides the dependency, then run `cargo test -p g2-storage -- --ignored`.
#[cfg(test)]
mod tests {
    use super::*;

    /// Connects to the Redis provided by `make redis-up` (override with
    /// `REDIS_URL`).
    async fn store() -> RedisStorage {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_owned());
        RedisStorage::connect(&url)
            .await
            .expect("Redis reachable — run `make redis-up` first")
    }

    /// Namespaces test keys per process so parallel/repeated runs never
    /// collide on the shared Redis.
    fn test_key(name: &str) -> String {
        format!("g2:testorg:it-{}:{name}", std::process::id())
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn set_get_delete_round_trip() {
        let store = store().await;
        let key = test_key("round-trip");
        store.set(&key, "v1", None).await.expect("set");
        assert_eq!(store.get(&key).await.expect("get"), Some("v1".into()));
        store.set(&key, "v2", None).await.expect("overwrite");
        assert_eq!(store.get(&key).await.expect("get"), Some("v2".into()));
        assert!(store.delete(&key).await.expect("delete"));
        assert_eq!(store.get(&key).await.expect("get after delete"), None);
        assert!(!store.delete(&key).await.expect("delete absent"));
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn ttl_expires_server_side() {
        let store = store().await;
        let key = test_key("ttl");
        store
            .set(&key, "v", Some(Duration::from_millis(150)))
            .await
            .expect("set with ttl");
        assert_eq!(store.get(&key).await.expect("get"), Some("v".into()));
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(store.get(&key).await.expect("get expired"), None);
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn set_without_ttl_clears_previous_ttl() {
        let store = store().await;
        let key = test_key("clear-ttl");
        store
            .set(&key, "v", Some(Duration::from_millis(200)))
            .await
            .expect("set with ttl");
        // Plain SET removes the pending expiry entirely.
        store.set(&key, "v", None).await.expect("set without ttl");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(store.get(&key).await.expect("get"), Some("v".into()));
        store.delete(&key).await.expect("cleanup");
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn clones_share_the_connection() {
        let a = store().await;
        let b = a.clone();
        let key = test_key("clone");
        a.set(&key, "v", None).await.expect("set via a");
        assert_eq!(b.get(&key).await.expect("get via b"), Some("v".into()));
        b.delete(&key).await.expect("cleanup");
    }

    #[tokio::test]
    async fn connect_to_bad_url_fails() {
        // Parse failure surfaces as Backend without any server involved.
        let err = RedisStorage::connect("not-a-redis-url").await.unwrap_err();
        assert!(matches!(err, StorageError::Backend(_)));
    }
}
