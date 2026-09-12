//! In-memory [`Storage`] implementation for unit tests and single-node dev runs.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
// tokio's Instant (not std's) so tests can pause and advance the clock.
use tokio::time::Instant;

use crate::{RateDecision, Storage, StorageError};

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

    /// Sliding-window request logs for [`Storage::check_rate`], keyed like
    /// the value map but holding timestamps instead of strings.
    windows: Arc<RwLock<HashMap<String, VecDeque<Instant>>>>,
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

    async fn check_rate(
        &self,
        key: &str,
        limit: u64,
        window: Duration,
    ) -> Result<RateDecision, StorageError> {
        let now = Instant::now();
        let mut windows = self.windows.write().await;
        let log = windows.entry(key.to_owned()).or_default();

        // Drop requests that have slid out of the window.
        while log.front().is_some_and(|&t| now - t >= window) {
            log.pop_front();
        }

        let count = log.len() as u64;
        // Until when the oldest recorded request keeps counting.
        let reset_after = |log: &VecDeque<Instant>| {
            log.front()
                .map_or(window, |&oldest| window.saturating_sub(now - oldest))
        };
        if count < limit {
            let reset_after = reset_after(log);
            log.push_back(now);
            Ok(RateDecision {
                allowed: true,
                remaining: limit - count - 1,
                reset_after,
            })
        } else {
            let reset_after = reset_after(log);
            if log.is_empty() {
                windows.remove(key); // limit == 0: keep the map clean
            }
            Ok(RateDecision {
                allowed: false,
                remaining: 0,
                reset_after,
            })
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

    mod check_rate {
        use super::*;

        const KEY: &str = "g2:default:ratelimit:k";
        const WINDOW: Duration = Duration::from_secs(10);

        #[tokio::test]
        async fn counts_down_then_denies() {
            tokio::time::pause();
            let store = MemoryStorage::new();

            for expected_remaining in [2, 1, 0] {
                let d = store.check_rate(KEY, 3, WINDOW).await.expect("check");
                assert!(d.allowed);
                assert_eq!(d.remaining, expected_remaining);
            }
            let d = store.check_rate(KEY, 3, WINDOW).await.expect("check");
            assert!(!d.allowed);
            assert_eq!(d.remaining, 0);
            assert_eq!(d.reset_after, WINDOW, "oldest request just arrived");
        }

        #[tokio::test]
        async fn window_slides_rather_than_resetting() {
            tokio::time::pause();
            let store = MemoryStorage::new();

            // Two requests, 6s apart, limit 2 per 10s.
            store.check_rate(KEY, 2, WINDOW).await.expect("first");
            tokio::time::advance(Duration::from_secs(6)).await;
            store.check_rate(KEY, 2, WINDOW).await.expect("second");

            // 9s in: the first request still occupies a slot.
            tokio::time::advance(Duration::from_secs(3)).await;
            let d = store.check_rate(KEY, 2, WINDOW).await.expect("third");
            assert!(!d.allowed);
            assert_eq!(d.reset_after, Duration::from_secs(1));

            // 11s in: the first slid out; the second (5s old) remains.
            tokio::time::advance(Duration::from_secs(2)).await;
            let d = store.check_rate(KEY, 2, WINDOW).await.expect("fourth");
            assert!(d.allowed, "a slot freed as the window slid");
            assert_eq!(d.remaining, 0);
        }

        #[tokio::test]
        async fn denied_requests_consume_no_slot() {
            tokio::time::pause();
            let store = MemoryStorage::new();

            store.check_rate(KEY, 1, WINDOW).await.expect("fill");
            for _ in 0..5 {
                let d = store.check_rate(KEY, 1, WINDOW).await.expect("denied");
                assert!(!d.allowed);
            }
            // Once the one recorded request expires, a slot frees — the five
            // denials must not have extended the window.
            tokio::time::advance(WINDOW).await;
            let d = store.check_rate(KEY, 1, WINDOW).await.expect("after");
            assert!(d.allowed);
        }

        #[tokio::test]
        async fn zero_limit_denies_everything() {
            let store = MemoryStorage::new();
            let d = store.check_rate(KEY, 0, WINDOW).await.expect("check");
            assert!(!d.allowed);
            assert_eq!(d.reset_after, WINDOW);
        }

        #[tokio::test]
        async fn keys_are_independent() {
            let store = MemoryStorage::new();
            store.check_rate("a", 1, WINDOW).await.expect("fill a");
            let d = store.check_rate("b", 1, WINDOW).await.expect("check b");
            assert!(d.allowed, "key `b` has its own window");
        }
    }
}
