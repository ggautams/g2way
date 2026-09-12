//! In-memory [`Storage`] implementation for unit tests and single-node dev runs.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
// tokio's Instant (not std's) so tests can pause and advance the clock.
use tokio::time::Instant;

use crate::{Storage, StorageError};

#[derive(Debug, Clone)]
struct Entry {
    value: String,
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|at| at <= now)
    }
}

/// A process-local [`Storage`] backed by a `HashMap`.
///
/// Not suitable for multi-pod deployments (state is not shared); it exists so
/// that middleware unit tests and local single-node runs need no Redis.
/// Cloning is cheap: clones share the same underlying map.
#[derive(Debug, Clone, Default)]
pub struct MemoryStorage {
    map: Arc<RwLock<HashMap<String, Entry>>>,
}

impl MemoryStorage {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl Storage for MemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        let now = Instant::now();
        // Fast path: read lock only.
        {
            let map = self.map.read().await;
            match map.get(key) {
                None => return Ok(None),
                Some(e) if !e.is_expired(now) => return Ok(Some(e.value.clone())),
                Some(_) => {} // expired: fall through to remove it
            }
        }
        // Lazily evict the expired entry.
        let mut map = self.map.write().await;
        if map.get(key).is_some_and(|e| e.is_expired(now)) {
            map.remove(key);
        }
        Ok(None)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StorageError> {
        let entry = Entry {
            value: value.to_owned(),
            expires_at: ttl.map(|t| Instant::now() + t),
        };
        self.map.write().await.insert(key.to_owned(), entry);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, StorageError> {
        let now = Instant::now();
        let mut map = self.map.write().await;
        match map.remove(key) {
            Some(e) => Ok(!e.is_expired(now)),
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_get_delete_round_trip() {
        let store = MemoryStorage::new();
        store.set("g2:default:k", "v1", None).await.expect("set");
        assert_eq!(
            store.get("g2:default:k").await.expect("get"),
            Some("v1".into())
        );
        assert!(store.delete("g2:default:k").await.expect("delete"));
        assert_eq!(store.get("g2:default:k").await.expect("get"), None);
        assert!(!store.delete("g2:default:k").await.expect("delete again"));
    }

    #[tokio::test]
    async fn set_overwrites_previous_value() {
        let store = MemoryStorage::new();
        store.set("k", "old", None).await.expect("set");
        store.set("k", "new", None).await.expect("set");
        assert_eq!(store.get("k").await.expect("get"), Some("new".into()));
    }

    #[tokio::test]
    async fn expired_entries_read_as_absent() {
        tokio::time::pause();
        let store = MemoryStorage::new();
        store
            .set("k", "v", Some(Duration::from_secs(5)))
            .await
            .expect("set");
        assert_eq!(store.get("k").await.expect("get"), Some("v".into()));
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(store.get("k").await.expect("get"), None);
        // Deleting an expired entry reports "nothing live was deleted".
        store
            .set("k2", "v", Some(Duration::from_secs(1)))
            .await
            .expect("set");
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!store.delete("k2").await.expect("delete"));
    }

    #[tokio::test]
    async fn clones_share_state() {
        let a = MemoryStorage::new();
        let b = a.clone();
        a.set("k", "v", None).await.expect("set");
        assert_eq!(b.get("k").await.expect("get"), Some("v".into()));
    }
}
