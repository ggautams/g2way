//! Storage abstraction for g2way.
//!
//! Every stateful gateway feature (API keys, rate-limit counters, quota
//! counters, config sync) goes through the [`Storage`] trait so that:
//!
//! - unit tests run against [`MemoryStorage`] with no external services, and
//! - production pods share state through [`RedisStorage`], where every pod
//!   points at the same Redis instance.
//!
//! # Key schema
//!
//! Keys are namespaced as `g2:{org_id}:{kind}:{id}` (for example
//! `g2:default:apikey:ab34…`). The `org_id` segment keeps the schema ready
//! for multi-organization support without a future data migration.

mod defs;
mod memory;
mod redis;

use std::time::Duration;

pub use defs::{load_api_definitions, DefinitionLoadError};
pub use memory::MemoryStorage;
pub use redis::RedisStorage;

/// A [`Storage`] shared across the gateway (routes, middleware, admin API).
pub type SharedStorage = std::sync::Arc<dyn Storage>;

/// Errors returned by [`Storage`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The backing store is unreachable or misbehaving.
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// The outcome of one limit check ([`Storage::check_rate`] or
/// [`Storage::check_quota`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitDecision {
    /// Whether the request fit inside the limit (and was recorded).
    pub allowed: bool,

    /// Requests left before the limit after this one (`0` when denied).
    pub remaining: u64,

    /// Time until the limit frees up: when the oldest recorded request
    /// slides out of a rate window, or when a quota period renews. The
    /// value behind `Retry-After` / `X-RateLimit-Reset` headers.
    pub reset_after: Duration,
}

/// Shared key-value state used by gateway features across pods.
///
/// Implementations must be cheap to clone or be used behind an `Arc`;
/// the gateway shares a single instance across all connections.
#[async_trait::async_trait]
pub trait Storage: Send + Sync + 'static {
    /// Fetches the value at `key`, or `None` if absent or expired.
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError>;

    /// Stores `value` at `key`, replacing any existing value.
    ///
    /// A `ttl` of `None` stores the value without expiry.
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), StorageError>;

    /// Deletes `key`, returning `true` if a live value was present.
    async fn delete(&self, key: &str) -> Result<bool, StorageError>;

    /// Lists every live key starting with `prefix`, in unspecified order.
    ///
    /// `prefix` is matched literally — characters that are glob syntax in a
    /// backend's pattern language must not act as wildcards. This is an
    /// enumeration primitive for infrequent control-plane work (loading API
    /// definitions, admin listings), not for the request path: backends may
    /// take time proportional to the whole keyspace.
    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError>;

    /// Atomically checks (and, when allowed, records) one request against a
    /// sliding window of at most `limit` requests per `window` at `key`.
    ///
    /// Sliding-window-log semantics: each allowed request is remembered
    /// with its timestamp and counts against the limit until exactly
    /// `window` has passed — there is no fixed-window boundary burst.
    /// **Denied requests are not recorded** and never consume a slot.
    ///
    /// A `limit` of `0` denies every request.
    async fn check_rate(
        &self,
        key: &str,
        limit: u64,
        window: Duration,
    ) -> Result<LimitDecision, StorageError>;

    /// Atomically counts one request against a **fixed-period** quota of at
    /// most `max` requests per `period` at `key`.
    ///
    /// Unlike [`check_rate`](Storage::check_rate) (a smoothing sliding
    /// window over seconds or minutes), a quota is a billing-style
    /// allowance over hours or days: the counter starts with the first
    /// request of a period and resets `period` after it — the reset
    /// timestamp is part of the contract
    /// (it is reported as [`LimitDecision::reset_after`]).
    ///
    /// A `max` of `0` denies every request.
    async fn check_quota(
        &self,
        key: &str,
        max: u64,
        period: Duration,
    ) -> Result<LimitDecision, StorageError>;
}
