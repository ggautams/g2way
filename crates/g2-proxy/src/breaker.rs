//! Per-route circuit breaking on live traffic.
//!
//! An API with a [`CircuitBreakerConfig`] gets one [`CircuitBreaker`] per
//! forwarding [`UpstreamTarget`](crate::UpstreamTarget), consulted by the
//! forwarder around every upstream exchange. Unlike the `health` module's
//! active probes (which evict individual addresses from the load-balancing
//! rotation), the breaker judges the route as a whole from the traffic it
//! actually serves: consecutive failures — transport errors, upstream
//! timeouts, `5xx` responses — open the circuit and requests are rejected
//! with `503` without contacting the upstream, shedding load until a
//! cooldown trial succeeds. State is pod-local, like the rotation itself.
//!
//! The state machine is the classic three-state breaker, kept lock-free for
//! the hot path (ADR-0001): the state tag and its transition timestamp are
//! packed into one `AtomicU64` so every transition is a single CAS, and the
//! consecutive-failure count lives in a separate relaxed counter (its races
//! only ever shift the trip point by a request or two, never corrupt state).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use g2_core::CircuitBreakerConfig;

/// State tag values packed into the high bits of [`CircuitBreaker::state`].
const CLOSED: u64 = 0;
const OPEN: u64 = 1;
const HALF_OPEN: u64 = 2;

/// Bits of the packed word carrying the transition timestamp (milliseconds
/// since the breaker's epoch): 62 bits ≈ 146 million years of uptime.
const SINCE_BITS: u32 = 62;
const SINCE_MASK: u64 = (1 << SINCE_BITS) - 1;

fn pack(state: u64, since_ms: u64) -> u64 {
    (state << SINCE_BITS) | (since_ms & SINCE_MASK)
}

fn unpack(word: u64) -> (u64, u64) {
    (word >> SINCE_BITS, word & SINCE_MASK)
}

/// Live circuit state for one route target.
///
/// The forwarder calls [`try_acquire`](Self::try_acquire) before contacting
/// the upstream and reports the exchange's final outcome (after any retries)
/// with [`record_success`](Self::record_success) /
/// [`record_failure`](Self::record_failure).
#[derive(Debug)]
pub(crate) struct CircuitBreaker {
    /// Packed `(state, transition timestamp)` word; see [`pack`].
    state: AtomicU64,
    /// Consecutive failures observed while closed; reset on success or trip.
    failures: AtomicU32,
    threshold: u32,
    cooldown_ms: u64,
    /// Timestamps are measured from here (monotonic; never system time).
    epoch: Instant,
    /// The owning API, for log lines.
    api_id: String,
}

impl CircuitBreaker {
    /// A closed breaker for `api_id` with `cfg`'s thresholds.
    pub(crate) fn new(cfg: &CircuitBreakerConfig, api_id: &str) -> Self {
        Self {
            state: AtomicU64::new(pack(CLOSED, 0)),
            failures: AtomicU32::new(0),
            threshold: cfg.failure_threshold,
            cooldown_ms: cfg.cooldown_ms,
            epoch: Instant::now(),
            api_id: api_id.to_owned(),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX) & SINCE_MASK
    }

    /// Whether a request may be forwarded now. `false` means the circuit is
    /// open: answer `503` without contacting the upstream.
    pub(crate) fn try_acquire(&self) -> bool {
        self.try_acquire_at(self.now_ms())
    }

    fn try_acquire_at(&self, now_ms: u64) -> bool {
        loop {
            let word = self.state.load(Ordering::Acquire);
            let (state, since) = unpack(word);
            if state == CLOSED {
                return true;
            }
            // Open (cooldown elapsed) and half-open (a trial that never
            // reported back — client gone mid-flight) both hand the next
            // request the trial slot after `cooldown_ms`; a fresh cooldown
            // or an in-flight trial rejects.
            if now_ms < since.saturating_add(self.cooldown_ms) {
                return false;
            }
            if self
                .state
                .compare_exchange(
                    word,
                    pack(HALF_OPEN, now_ms),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                tracing::info!(api_id = %self.api_id, "circuit half-open; letting a trial request through");
                return true;
            }
            // Lost the trial race; re-evaluate the new state.
        }
    }

    /// Records a successful upstream exchange.
    pub(crate) fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        let word = self.state.load(Ordering::Acquire);
        let (state, _) = unpack(word);
        // Only a half-open trial's success closes the circuit; a straggler
        // success from a request admitted before the trip is stale evidence
        // and must not close an open circuit.
        if state == HALF_OPEN
            && self
                .state
                .compare_exchange(word, pack(CLOSED, 0), Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            tracing::info!(api_id = %self.api_id, "trial succeeded; circuit closed");
        }
    }

    /// Records a failed upstream exchange (transport error, timeout, or
    /// `5xx` response).
    pub(crate) fn record_failure(&self) {
        self.record_failure_at(self.now_ms());
    }

    fn record_failure_at(&self, now_ms: u64) {
        let word = self.state.load(Ordering::Acquire);
        match unpack(word).0 {
            HALF_OPEN => {
                if self
                    .state
                    .compare_exchange(
                        word,
                        pack(OPEN, now_ms),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    tracing::warn!(api_id = %self.api_id, "trial failed; circuit re-opened");
                }
            }
            CLOSED => {
                let failures = self
                    .failures
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                if failures >= self.threshold
                    && self
                        .state
                        .compare_exchange(
                            word,
                            pack(OPEN, now_ms),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                {
                    self.failures.store(0, Ordering::Relaxed);
                    tracing::warn!(
                        api_id = %self.api_id,
                        failures,
                        "circuit opened after consecutive upstream failures"
                    );
                }
            }
            // Already open: stragglers neither extend nor shorten the
            // cooldown.
            _ => {}
        }
    }

    /// The current state's serialized name — for status/dashboard APIs. An
    /// elapsed cooldown still reads `"open"` until a request claims the
    /// trial slot.
    pub(crate) fn state_name(&self) -> &'static str {
        match unpack(self.state.load(Ordering::Acquire)).0 {
            OPEN => "open",
            HALF_OPEN => "half_open",
            _ => "closed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker(threshold: u32, cooldown_ms: u64) -> CircuitBreaker {
        CircuitBreaker::new(
            &CircuitBreakerConfig {
                failure_threshold: threshold,
                cooldown_ms,
            },
            "test",
        )
    }

    #[test]
    fn opens_after_consecutive_failures_only() {
        let b = breaker(3, 1_000);
        b.record_failure_at(0);
        b.record_failure_at(1);
        // A success resets the streak.
        b.record_success();
        b.record_failure_at(2);
        b.record_failure_at(3);
        assert!(
            b.try_acquire_at(4),
            "two consecutive failures must not trip"
        );
        b.record_failure_at(5);
        assert!(!b.try_acquire_at(6), "third consecutive failure must trip");
        assert_eq!(b.state_name(), "open");
    }

    #[test]
    fn trial_after_cooldown_closes_on_success() {
        let b = breaker(1, 1_000);
        b.record_failure_at(100);
        assert!(!b.try_acquire_at(1_099), "cooldown still running");
        assert!(b.try_acquire_at(1_100), "cooldown elapsed grants the trial");
        assert_eq!(b.state_name(), "half_open");
        assert!(!b.try_acquire_at(1_101), "only one trial in flight");
        b.record_success();
        assert_eq!(b.state_name(), "closed");
        assert!(b.try_acquire_at(1_102));
    }

    #[test]
    fn trial_failure_reopens_for_another_cooldown() {
        let b = breaker(1, 1_000);
        b.record_failure_at(0);
        assert!(b.try_acquire_at(1_000));
        b.record_failure_at(1_050);
        assert_eq!(b.state_name(), "open");
        assert!(
            !b.try_acquire_at(2_000),
            "cooldown restarts from the trial failure"
        );
        assert!(b.try_acquire_at(2_050));
    }

    #[test]
    fn abandoned_trial_slot_is_reclaimed_after_a_cooldown() {
        let b = breaker(1, 1_000);
        b.record_failure_at(0);
        assert!(b.try_acquire_at(1_000), "first trial");
        // The trial never reports back (client disconnected mid-flight);
        // one cooldown later the slot is handed out again.
        assert!(!b.try_acquire_at(1_999));
        assert!(b.try_acquire_at(2_000), "stuck trial reclaimed");
    }

    #[test]
    fn straggler_success_does_not_close_an_open_circuit() {
        let b = breaker(1, 1_000);
        b.record_failure_at(0);
        assert_eq!(b.state_name(), "open");
        // A request admitted before the trip finishes late and succeeds.
        b.record_success();
        assert_eq!(b.state_name(), "open");
        assert!(!b.try_acquire_at(500));
    }
}
