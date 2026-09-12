//! Storage abstraction for g2way.
//!
//! Every stateful gateway feature (API keys, rate-limit counters, quota
//! counters, config sync) goes through the [`Storage`] trait so that:
//!
//! - unit tests run against [`MemoryStorage`] with no external services, and
//! - production pods share state through the Redis implementation
//!   (added in milestone M2; see `ROADMAP.md`).
//!
//! # Key schema
//!
//! Keys are namespaced as `g2:{org_id}:{kind}:{id}` (for example
//! `g2:default:apikey:ab34…`). The `org_id` segment keeps the schema ready
//! for multi-organization support without a future data migration.

mod memory;

use std::time::Duration;

pub use memory::MemoryStorage;

/// Errors returned by [`Storage`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The backing store is unreachable or misbehaving.
    #[error("storage backend error: {0}")]
    Backend(String),
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
}
