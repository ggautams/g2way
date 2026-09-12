//! [`SpikeGuard`]: a pod-local token bucket shedding load before Redis.
//!
//! The distributed rate limiter ([`check_rate`](g2_storage::Storage::check_rate))
//! costs one Redis round-trip per request. A traffic spike — or an attacker
//! hammering one key — would translate directly into Redis load. The spike
//! guard is a **per-pod, in-process** token bucket consulted first: when an
//! identity's bucket is empty the request is rejected locally and Redis is
//! never asked.
//!
//! It is deliberately coarse, a pressure-relief valve rather than the limit
//! itself (that stays in Redis, shared across pods):
//!
//! - Buckets refill at whole-second granularity; the burst `capacity`
//!   absorbs sub-second traffic.
//! - Identities are hashed into a **fixed shard array**: two identities may
//!   share a bucket, which can only make the guard stricter, never looser.
//! - State is a packed `AtomicU64` per shard — no locks, no per-request
//!   allocation, fixed memory (hot-path rules, ADR-0001).

use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use g2_core::config::SpikeGuardConfig;

/// Number of token buckets. Identities are hashed onto them, so this bounds
/// memory (8 bytes per bucket) at the cost of occasional sharing.
const SHARDS: usize = 4096;

/// A pod-local, lock-free token-bucket rate guard.
///
/// See the [module docs](self) for what it is (and is not) for. Construct
/// one per gateway process from the configured [`SpikeGuardConfig`] and
/// share it via `Arc`.
pub struct SpikeGuard {
    /// Reference point for bucket timestamps (seconds since construction).
    epoch: Instant,
    capacity: u32,
    refill_per_sec: u32,
    hasher: RandomState,
    /// One packed bucket per shard: high 32 bits = seconds (since `epoch`)
    /// of the last refill credit, low 32 bits = tokens available.
    buckets: Box<[AtomicU64]>,
}

impl std::fmt::Debug for SpikeGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpikeGuard")
            .field("capacity", &self.capacity)
            .field("refill_per_sec", &self.refill_per_sec)
            .field("shards", &SHARDS)
            .finish_non_exhaustive()
    }
}

const fn pack(last_refill_secs: u32, tokens: u32) -> u64 {
    ((last_refill_secs as u64) << 32) | tokens as u64
}

const fn unpack(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, packed as u32)
}

impl SpikeGuard {
    /// Builds a guard from `cfg` with every bucket starting full.
    ///
    /// `cfg` should have passed
    /// [`GatewayConfig::validate`](g2_core::GatewayConfig::validate); a zero
    /// capacity or refill rate would make the guard deny everything.
    #[must_use]
    pub fn new(cfg: &SpikeGuardConfig) -> Self {
        let buckets = (0..SHARDS)
            .map(|_| AtomicU64::new(pack(0, cfg.capacity)))
            .collect();
        Self {
            epoch: Instant::now(),
            capacity: cfg.capacity,
            refill_per_sec: cfg.refill_per_sec,
            hasher: RandomState::new(),
            buckets,
        }
    }

    /// Takes one token from `identity`'s bucket; `false` means the local
    /// burst allowance is exhausted and the request should be rejected
    /// without consulting Redis.
    #[must_use]
    pub fn try_acquire(&self, identity: &str) -> bool {
        // Saturates ~136 years after startup; by then every bucket simply
        // stays fully refilled.
        let now_secs = u32::try_from(self.epoch.elapsed().as_secs()).unwrap_or(u32::MAX);
        self.try_acquire_at(identity, now_secs)
    }

    /// Clock-explicit core of [`Self::try_acquire`] (tests pass the time).
    fn try_acquire_at(&self, identity: &str, now_secs: u32) -> bool {
        let bucket = &self.buckets[self.shard(identity)];
        let mut current = bucket.load(Ordering::Relaxed);
        loop {
            let (last_refill, tokens) = unpack(current);
            let elapsed = now_secs.saturating_sub(last_refill);
            // Credit refill only at whole-second boundaries, and advance
            // the timestamp only when crediting — otherwise sub-second
            // traffic would reset the clock forever and starve the bucket.
            let (new_last, available) = if elapsed > 0 {
                let refilled =
                    u64::from(tokens) + u64::from(elapsed) * u64::from(self.refill_per_sec);
                (
                    now_secs,
                    u32::try_from(refilled)
                        .unwrap_or(u32::MAX)
                        .min(self.capacity),
                )
            } else {
                (last_refill, tokens)
            };
            if available == 0 {
                // Nothing written: pending refill credit stays computable
                // from the old timestamp.
                return false;
            }
            let next = pack(new_last, available - 1);
            match bucket.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// The shard index `identity` maps to.
    fn shard(&self, identity: &str) -> usize {
        (self.hasher.hash_one(identity) as usize) % self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(capacity: u32, refill_per_sec: u32) -> SpikeGuard {
        SpikeGuard::new(&SpikeGuardConfig {
            capacity,
            refill_per_sec,
        })
    }

    #[test]
    fn burst_up_to_capacity_then_denies() {
        let g = guard(3, 1);
        for _ in 0..3 {
            assert!(g.try_acquire_at("id", 0));
        }
        assert!(!g.try_acquire_at("id", 0));
    }

    #[test]
    fn refills_at_whole_seconds_up_to_capacity() {
        let g = guard(5, 2);
        for _ in 0..5 {
            assert!(g.try_acquire_at("id", 0));
        }
        assert!(!g.try_acquire_at("id", 0));

        // One second later: 2 tokens back.
        assert!(g.try_acquire_at("id", 1));
        assert!(g.try_acquire_at("id", 1));
        assert!(!g.try_acquire_at("id", 1));

        // A long idle stretch refills to capacity, not beyond.
        for _ in 0..5 {
            assert!(g.try_acquire_at("id", 1000));
        }
        assert!(!g.try_acquire_at("id", 1000));
    }

    #[test]
    fn constant_denied_traffic_does_not_starve_refill() {
        let g = guard(1, 1);
        assert!(g.try_acquire_at("id", 0));
        // A flood of denied requests within the same second must not push
        // the refill point forward.
        for _ in 0..100 {
            assert!(!g.try_acquire_at("id", 0));
        }
        assert!(g.try_acquire_at("id", 1), "refill still lands at t=1");
    }

    #[test]
    fn identities_in_distinct_shards_are_independent() {
        let g = guard(1, 1);
        // The hasher is seeded per guard: find two identities that land in
        // different shards rather than assuming any fixed pair does.
        let a = "identity-a";
        let b = (0..)
            .map(|i| format!("identity-b-{i}"))
            .find(|b| g.shard(b) != g.shard(a))
            .expect("some identity lands in another shard");

        assert!(g.try_acquire_at(a, 0));
        assert!(!g.try_acquire_at(a, 0), "a exhausted");
        assert!(g.try_acquire_at(&b, 0), "b unaffected");
    }

    #[test]
    fn colliding_identities_share_a_bucket_strictly() {
        let g = guard(1, 1);
        let a = "identity-a";
        // Sharing a shard only ever makes the guard stricter.
        let b = (0..)
            .map(|i| format!("identity-b-{i}"))
            .find(|b| g.shard(b) == g.shard(a))
            .expect("some identity collides");
        assert!(g.try_acquire_at(a, 0));
        assert!(!g.try_acquire_at(&b, 0));
    }

    #[test]
    fn concurrent_acquires_never_exceed_capacity() {
        let g = std::sync::Arc::new(guard(100, 1));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let g = std::sync::Arc::clone(&g);
            handles.push(std::thread::spawn(move || {
                (0..50).filter(|_| g.try_acquire_at("id", 0)).count()
            }));
        }
        let total: usize = handles.into_iter().map(|h| h.join().expect("join")).sum();
        assert_eq!(total, 100, "exactly `capacity` acquisitions succeed");
    }
}
