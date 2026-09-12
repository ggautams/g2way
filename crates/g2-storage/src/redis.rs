//! Redis-backed [`Storage`] implementation for multi-pod deployments.

use std::sync::Arc;
use std::time::Duration;

// `::redis` disambiguates the extern crate from this module (also `redis`).
use ::redis::aio::ConnectionManager;
use ::redis::Script;

use crate::{LimitDecision, Storage, StorageError};

fn backend_err(e: ::redis::RedisError) -> StorageError {
    StorageError::Backend(e.to_string())
}

/// Escapes Redis glob-pattern metacharacters (`* ? [ ] \`) so a
/// [`Storage::scan_prefix`] prefix always matches literally.
fn escape_glob(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Sliding-window-log rate check, executed atomically inside Redis.
///
/// Uses the **Redis server's clock** (`TIME`), so every gateway pod sees
/// the same window regardless of pod clock skew. The log is a sorted set
/// scored by milliseconds; `ARGV[3]` makes concurrent members unique.
/// Returns `{allowed (0|1), remaining, reset_after_ms}`.
const RATE_SCRIPT: &str = r"
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local reset = window
if oldest[2] then
    reset = tonumber(oldest[2]) + window - now
    if reset < 0 then reset = 0 end
end
if count < limit then
    redis.call('ZADD', KEYS[1], now, now .. '-' .. ARGV[3])
    redis.call('PEXPIRE', KEYS[1], window)
    return {1, limit - count - 1, reset}
end
return {0, 0, reset}
";

/// Fixed-period quota count, executed atomically inside Redis.
///
/// A plain counter whose TTL is the period: it starts with the first
/// request of a period (`INCR` → 1 sets the expiry) and the reset
/// timestamp is simply the key's remaining TTL. Counting denied requests
/// too is harmless — the key is already over `max` — and never extends
/// the period. Returns `{allowed (0|1), remaining, reset_after_ms}`.
const QUOTA_SCRIPT: &str = r"
local max = tonumber(ARGV[1])
local period = tonumber(ARGV[2])
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('PEXPIRE', KEYS[1], period)
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
    -- Defensive: a counter that somehow lost its expiry must not deny
    -- forever; restart its period.
    redis.call('PEXPIRE', KEYS[1], period)
    ttl = period
end
if count > max then
    return {0, 0, ttl}
end
return {1, max - count, ttl}
";

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
    /// Cached rate-limit script (EVALSHA after the first call).
    rate_script: Arc<Script>,
    /// Cached quota script (EVALSHA after the first call).
    quota_script: Arc<Script>,
}

impl Clone for RedisStorage {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            rate_script: Arc::clone(&self.rate_script),
            quota_script: Arc::clone(&self.quota_script),
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
        Ok(Self {
            conn,
            rate_script: Arc::new(Script::new(RATE_SCRIPT)),
            quota_script: Arc::new(Script::new(QUOTA_SCRIPT)),
        })
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

    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let pattern = format!("{}*", escape_glob(prefix));
        let mut conn = self.conn.clone();
        let mut keys = Vec::new();
        let mut cursor: u64 = 0;
        // Cursor-based SCAN never blocks the server the way KEYS would; the
        // cursor lives in the command itself, so a shared multiplexed
        // connection is fine.
        loop {
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .map_err(backend_err)?;
            keys.extend(batch);
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        // A full SCAN iteration guarantees every key at least once, not
        // exactly once.
        keys.sort_unstable();
        keys.dedup();
        Ok(keys)
    }

    async fn check_rate(
        &self,
        key: &str,
        limit: u64,
        window: Duration,
    ) -> Result<LimitDecision, StorageError> {
        // The script compares against ms; clamp like `set` does for PX.
        let window_ms = u64::try_from(window.as_millis()).unwrap_or(u64::MAX).max(1);
        // Uniquifies members: two requests landing in the same millisecond
        // must not collapse into one sorted-set entry.
        let member_suffix: u64 = rand::random();
        let (allowed, remaining, reset_ms): (u8, u64, u64) = self
            .rate_script
            .key(key)
            .arg(window_ms)
            .arg(limit)
            .arg(member_suffix)
            .invoke_async(&mut self.conn.clone())
            .await
            .map_err(backend_err)?;
        Ok(LimitDecision {
            allowed: allowed == 1,
            remaining,
            reset_after: Duration::from_millis(reset_ms),
        })
    }

    async fn check_quota(
        &self,
        key: &str,
        max: u64,
        period: Duration,
    ) -> Result<LimitDecision, StorageError> {
        let period_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX).max(1);
        let (allowed, remaining, reset_ms): (u8, u64, u64) = self
            .quota_script
            .key(key)
            .arg(max)
            .arg(period_ms)
            .invoke_async(&mut self.conn.clone())
            .await
            .map_err(backend_err)?;
        Ok(LimitDecision {
            allowed: allowed == 1,
            remaining,
            reset_after: Duration::from_millis(reset_ms),
        })
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

    #[test]
    fn escape_glob_escapes_metacharacters() {
        assert_eq!(escape_glob("g2:default:apidef:"), "g2:default:apidef:");
        assert_eq!(escape_glob(r"a*b?c[d]e\f"), r"a\*b\?c\[d\]e\\f");
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn scan_prefix_lists_only_matching_keys() {
        let store = store().await;
        let prefix = test_key("scan:");
        let sibling = test_key("scan-sibling");
        store.set(&format!("{prefix}b"), "v", None).await.unwrap();
        store.set(&format!("{prefix}a"), "v", None).await.unwrap();
        store.set(&sibling, "v", None).await.unwrap();

        let keys = store.scan_prefix(&prefix).await.expect("scan");
        assert_eq!(keys, [format!("{prefix}a"), format!("{prefix}b")]);

        for k in keys.iter().chain(std::iter::once(&sibling)) {
            store.delete(k).await.expect("cleanup");
        }
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn scan_prefix_treats_glob_characters_literally() {
        let store = store().await;
        // Unescaped, `[an]` is a character class that would match the decoy
        // key `…sca:x`; the literal `…sc[an]:x` is the only valid hit.
        let literal = test_key("sc[an]:x");
        let decoy = test_key("sca:x");
        store.set(&literal, "v", None).await.unwrap();
        store.set(&decoy, "v", None).await.unwrap();

        let keys = store.scan_prefix(&test_key("sc[an]:")).await.expect("scan");
        assert_eq!(keys, std::slice::from_ref(&literal));

        store.delete(&literal).await.expect("cleanup");
        store.delete(&decoy).await.expect("cleanup");
    }

    #[tokio::test]
    async fn connect_to_bad_url_fails() {
        // Parse failure surfaces as Backend without any server involved.
        let err = RedisStorage::connect("not-a-redis-url").await.unwrap_err();
        assert!(matches!(err, StorageError::Backend(_)));
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn rate_burst_fills_then_denies_then_slides() {
        let store = store().await;
        let key = test_key("rate-burst");
        let window = Duration::from_millis(500);

        for expected_remaining in [2, 1, 0] {
            let d = store.check_rate(&key, 3, window).await.expect("check");
            assert!(d.allowed);
            assert_eq!(d.remaining, expected_remaining);
        }
        let d = store.check_rate(&key, 3, window).await.expect("denied");
        assert!(!d.allowed);
        assert!(
            d.reset_after <= window && d.reset_after > Duration::ZERO,
            "reset_after within the window, got {:?}",
            d.reset_after
        );

        // After the window slides past the burst, slots free again.
        tokio::time::sleep(window + Duration::from_millis(100)).await;
        let d = store.check_rate(&key, 3, window).await.expect("after");
        assert!(d.allowed);
        assert_eq!(d.remaining, 2, "all three slots freed");
        store.delete(&key).await.expect("cleanup");
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn rate_check_is_atomic_under_concurrency() {
        let store = store().await;
        let key = test_key("rate-atomic");
        let window = Duration::from_secs(5);

        // 20 concurrent checks against a limit of 5: the Lua script must
        // admit exactly 5 (this is the multi-pod correctness property —
        // concurrent EVALs are serialized inside Redis).
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let store = store.clone();
            let key = key.clone();
            tasks.spawn(async move { store.check_rate(&key, 5, window).await.expect("check") });
        }
        let allowed = tasks
            .join_all()
            .await
            .into_iter()
            .filter(|d| d.allowed)
            .count();
        assert_eq!(allowed, 5);
        store.delete(&key).await.expect("cleanup");
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn quota_fills_denies_then_renews() {
        let store = store().await;
        let key = test_key("quota");
        let period = Duration::from_millis(500);

        for expected_remaining in [1, 0] {
            let d = store.check_quota(&key, 2, period).await.expect("check");
            assert!(d.allowed);
            assert_eq!(d.remaining, expected_remaining);
        }
        let d = store.check_quota(&key, 2, period).await.expect("denied");
        assert!(!d.allowed);
        assert!(
            d.reset_after <= period && d.reset_after > Duration::ZERO,
            "reset within the period, got {:?}",
            d.reset_after
        );

        tokio::time::sleep(period + Duration::from_millis(100)).await;
        let d = store.check_quota(&key, 2, period).await.expect("renewed");
        assert!(d.allowed);
        assert_eq!(d.remaining, 1, "whole allowance renewed");
        store.delete(&key).await.expect("cleanup");
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn quota_check_is_atomic_under_concurrency() {
        let store = store().await;
        let key = test_key("quota-atomic");
        let period = Duration::from_secs(5);

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let store = store.clone();
            let key = key.clone();
            tasks.spawn(async move { store.check_quota(&key, 5, period).await.expect("check") });
        }
        let allowed = tasks
            .join_all()
            .await
            .into_iter()
            .filter(|d| d.allowed)
            .count();
        assert_eq!(allowed, 5);
        store.delete(&key).await.expect("cleanup");
    }

    #[tokio::test]
    #[ignore = "needs a real Redis: `make redis-up`"]
    async fn rate_zero_limit_denies() {
        let store = store().await;
        let key = test_key("rate-zero");
        let d = store
            .check_rate(&key, 0, Duration::from_secs(1))
            .await
            .expect("check");
        assert!(!d.allowed);
    }
}
