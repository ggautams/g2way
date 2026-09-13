//! In-memory [`Storage`] implementation for unit tests and single-node dev runs.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
// tokio's Instant (not std's) so tests can pause and advance the clock.
use tokio::time::Instant;

use crate::{LimitDecision, Storage, StorageError};

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

    /// Fixed-period counters for [`Storage::check_quota`]: requests so far
    /// and when the period renews.
    quotas: Arc<RwLock<HashMap<String, QuotaEntry>>>,

    /// Pub/sub fan-out per channel for [`Storage::publish`]/`subscribe`.
    /// Senders are created lazily on first use of a channel.
    channels: Arc<RwLock<HashMap<String, tokio::sync::broadcast::Sender<String>>>>,

    /// FIFO lists for [`Storage::list_append`]/[`Storage::list_drain`].
    lists: Arc<RwLock<HashMap<String, VecDeque<String>>>>,
}

#[derive(Debug, Clone, Copy)]
struct QuotaEntry {
    count: u64,
    resets_at: Instant,
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

    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let now = Instant::now();
        let map = self.map.read().await;
        Ok(map
            .iter()
            .filter(|(k, e)| k.starts_with(prefix) && !e.is_expired(now))
            .map(|(k, _)| k.clone())
            .collect())
    }

    async fn list_append(
        &self,
        key: &str,
        values: &[String],
        max_len: Option<u64>,
    ) -> Result<(), StorageError> {
        if values.is_empty() {
            return Ok(());
        }
        let mut lists = self.lists.write().await;
        let list = lists.entry(key.to_owned()).or_default();
        list.extend(values.iter().cloned());
        if let Some(max) = max_len {
            let max = usize::try_from(max).unwrap_or(usize::MAX);
            while list.len() > max {
                list.pop_front(); // keep the newest entries
            }
        }
        Ok(())
    }

    async fn list_drain(&self, key: &str, max: usize) -> Result<Vec<String>, StorageError> {
        let mut lists = self.lists.write().await;
        let Some(list) = lists.get_mut(key) else {
            return Ok(Vec::new());
        };
        let drained: Vec<String> = list.drain(..max.min(list.len())).collect();
        if list.is_empty() {
            lists.remove(key);
        }
        Ok(drained)
    }

    async fn publish(&self, channel: &str, payload: &str) -> Result<(), StorageError> {
        let channels = self.channels.read().await;
        if let Some(sender) = channels.get(channel) {
            // A send error just means no live subscribers: fine for
            // fire-and-forget fan-out.
            let _ = sender.send(payload.to_owned());
        }
        Ok(())
    }

    async fn subscribe(
        &self,
        channel: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<String>, StorageError> {
        let mut channels = self.channels.write().await;
        let sender = channels
            .entry(channel.to_owned())
            .or_insert_with(|| tokio::sync::broadcast::channel(32).0);
        let mut broadcast_rx = sender.subscribe();
        drop(channels);

        // Adapt broadcast → mpsc so the trait exposes one receiver type.
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(msg) => {
                        if tx.send(msg).await.is_err() {
                            return; // subscriber dropped its receiver
                        }
                    }
                    // Lagged: older messages were dropped, keep receiving —
                    // best-effort delivery is the contract.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        Ok(rx)
    }

    async fn check_rate(
        &self,
        key: &str,
        limit: u64,
        window: Duration,
    ) -> Result<LimitDecision, StorageError> {
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
            Ok(LimitDecision {
                allowed: true,
                remaining: limit - count - 1,
                reset_after,
            })
        } else {
            let reset_after = reset_after(log);
            if log.is_empty() {
                windows.remove(key); // limit == 0: keep the map clean
            }
            Ok(LimitDecision {
                allowed: false,
                remaining: 0,
                reset_after,
            })
        }
    }

    async fn check_quota(
        &self,
        key: &str,
        max: u64,
        period: Duration,
    ) -> Result<LimitDecision, StorageError> {
        let now = Instant::now();
        let mut quotas = self.quotas.write().await;
        let entry = quotas.entry(key.to_owned()).or_insert(QuotaEntry {
            count: 0,
            resets_at: now + period,
        });
        if entry.resets_at <= now {
            // The period elapsed: this request starts a fresh one.
            *entry = QuotaEntry {
                count: 0,
                resets_at: now + period,
            };
        }
        entry.count += 1;
        let reset_after = entry.resets_at.saturating_duration_since(now);
        if entry.count > max {
            Ok(LimitDecision {
                allowed: false,
                remaining: 0,
                reset_after,
            })
        } else {
            Ok(LimitDecision {
                allowed: true,
                remaining: max - entry.count,
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
    async fn scan_prefix_filters_by_prefix_and_liveness() {
        tokio::time::pause();
        let store = MemoryStorage::new();
        store.set("g2:default:apidef:a", "{}", None).await.unwrap();
        store.set("g2:default:apidef:b", "{}", None).await.unwrap();
        store.set("g2:other:apidef:c", "{}", None).await.unwrap();
        store
            .set("g2:default:apidef:gone", "{}", Some(Duration::from_secs(1)))
            .await
            .unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;

        let mut keys = store.scan_prefix("g2:default:apidef:").await.expect("scan");
        keys.sort();
        assert_eq!(keys, ["g2:default:apidef:a", "g2:default:apidef:b"]);
        assert!(store
            .scan_prefix("g2:missing:")
            .await
            .expect("scan")
            .is_empty());
    }

    #[tokio::test]
    async fn lists_append_and_drain_in_fifo_order() {
        let store = MemoryStorage::new();
        let key = "g2:default:analytics:records";
        store
            .list_append(key, &["a".into(), "b".into()], None)
            .await
            .expect("append");
        store
            .list_append(key, &["c".into()], None)
            .await
            .expect("append more");

        assert_eq!(store.list_drain(key, 2).await.expect("drain"), ["a", "b"]);
        assert_eq!(store.list_drain(key, 10).await.expect("drain rest"), ["c"]);
        assert!(store.list_drain(key, 10).await.expect("empty").is_empty());
        assert!(store
            .list_drain("never-written", 10)
            .await
            .expect("absent")
            .is_empty());
    }

    #[tokio::test]
    async fn list_append_caps_at_max_len_keeping_newest() {
        let store = MemoryStorage::new();
        let key = "g2:default:analytics:records";
        for v in ["1", "2", "3"] {
            store
                .list_append(key, &[v.to_owned()], Some(2))
                .await
                .expect("append");
        }
        assert_eq!(store.list_drain(key, 10).await.expect("drain"), ["2", "3"]);
        // An empty append is a no-op, not an error.
        store.list_append(key, &[], Some(2)).await.expect("empty");
    }

    #[tokio::test]
    async fn publish_reaches_every_subscriber_on_the_channel() {
        let store = MemoryStorage::new();
        let mut a = store.subscribe("g2:default:channel:reload").await.unwrap();
        let mut b = store.subscribe("g2:default:channel:reload").await.unwrap();
        let mut other = store.subscribe("g2:default:channel:other").await.unwrap();

        store
            .publish("g2:default:channel:reload", "nudge")
            .await
            .expect("publish");

        assert_eq!(a.recv().await.as_deref(), Some("nudge"));
        assert_eq!(b.recv().await.as_deref(), Some("nudge"));
        // The unrelated channel saw nothing.
        assert!(other.try_recv().is_err());
    }

    #[tokio::test]
    async fn publish_without_subscribers_is_ok() {
        let store = MemoryStorage::new();
        store
            .publish("g2:default:channel:reload", "into the void")
            .await
            .expect("publish");
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

    mod check_quota {
        use super::*;

        const KEY: &str = "g2:default:quota:k";
        const PERIOD: Duration = Duration::from_secs(3600);

        #[tokio::test]
        async fn counts_down_then_denies() {
            tokio::time::pause();
            let store = MemoryStorage::new();

            for expected_remaining in [1, 0] {
                let d = store.check_quota(KEY, 2, PERIOD).await.expect("check");
                assert!(d.allowed);
                assert_eq!(d.remaining, expected_remaining);
            }
            let d = store.check_quota(KEY, 2, PERIOD).await.expect("check");
            assert!(!d.allowed);
            assert_eq!(d.reset_after, PERIOD, "period started with request one");
        }

        #[tokio::test]
        async fn period_is_fixed_not_sliding() {
            tokio::time::pause();
            let store = MemoryStorage::new();

            store.check_quota(KEY, 1, PERIOD).await.expect("fill");
            // Halfway through, still denied — and the denial must not
            // extend the period.
            tokio::time::advance(PERIOD / 2).await;
            let d = store.check_quota(KEY, 1, PERIOD).await.expect("denied");
            assert!(!d.allowed);
            assert_eq!(d.reset_after, PERIOD / 2);

            // Once the period from the *first* request elapses, the whole
            // allowance renews at once (fixed window, unlike check_rate).
            tokio::time::advance(PERIOD / 2).await;
            let d = store.check_quota(KEY, 1, PERIOD).await.expect("renewed");
            assert!(d.allowed);
            assert_eq!(d.reset_after, PERIOD, "fresh period starts now");
        }

        #[tokio::test]
        async fn zero_max_denies_everything() {
            let store = MemoryStorage::new();
            let d = store.check_quota(KEY, 0, PERIOD).await.expect("check");
            assert!(!d.allowed);
        }

        #[tokio::test]
        async fn keys_are_independent() {
            let store = MemoryStorage::new();
            store.check_quota("a", 1, PERIOD).await.expect("fill a");
            let d = store.check_quota("b", 1, PERIOD).await.expect("check b");
            assert!(d.allowed, "key `b` has its own quota");
        }
    }
}
