//! Process-level gateway configuration.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Error;

fn default_listen_addr() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("valid default listen addr")
}

fn default_apps_dir() -> PathBuf {
    PathBuf::from("./apps")
}

/// Pub/sub channel a config-reload nudge for `org_id` is broadcast on:
/// `g2:{org_id}:channel:reload`.
///
/// The message payload carries no data — receivers re-read definitions
/// from storage and rebuild their route table (see ADR-0002).
#[must_use]
pub fn reload_channel(org_id: &str) -> String {
    format!("g2:{org_id}:channel:reload")
}

/// Settings for the pod-local token-bucket spike guard placed in front of
/// the distributed (Redis) rate limiter.
///
/// The guard sheds excess per-identity traffic locally before it costs a
/// Redis round-trip; the authoritative limit stays in Redis. Absent from
/// the config means the guard is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpikeGuardConfig {
    /// Burst size: tokens an idle identity accumulates (must be > 0).
    pub capacity: u32,

    /// Tokens credited back per second (must be > 0). Refill happens at
    /// whole-second granularity; `capacity` absorbs sub-second bursts.
    pub refill_per_sec: u32,
}

/// Process-level settings for a gateway node.
///
/// Loaded from an optional YAML/JSON file, with individual fields
/// overridable by the binary's CLI flags and environment variables (the
/// binary applies overrides after calling [`GatewayConfig::from_file`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayConfig {
    /// Address the proxy listener binds to.
    pub listen_addr: SocketAddr,

    /// Directory scanned for API definition files (`*.json`, `*.yaml`, `*.yml`).
    pub apps_dir: PathBuf,

    /// Grace period in seconds to let in-flight requests finish on shutdown.
    pub shutdown_grace_period_secs: u64,

    /// Redis connection URL (e.g. `redis://redis.g2way.svc:6379/`). When
    /// unset, the gateway falls back to process-local in-memory storage:
    /// fine for keyless dev runs, but API keys are then neither shared
    /// across pods nor persisted.
    pub redis_url: Option<String>,

    /// Address the admin API binds to (a **separate** listener from the
    /// proxy, so it can stay off the public network). `None` — the default —
    /// disables the admin API entirely.
    pub admin_listen_addr: Option<SocketAddr>,

    /// Shared secret admin requests must present in the
    /// `X-G2-Authorization` header. Required (non-empty) whenever
    /// `admin_listen_addr` is set: the admin API never runs unsecured.
    pub admin_secret: Option<String>,

    /// Pod-local spike guard in front of the distributed rate limiter.
    /// `None` (the default) disables it.
    pub spike_guard: Option<SpikeGuardConfig>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            apps_dir: default_apps_dir(),
            shutdown_grace_period_secs: 30,
            redis_url: None,
            admin_listen_addr: None,
            admin_secret: None,
            spike_guard: None,
        }
    }
}

impl GatewayConfig {
    /// Loads configuration from a YAML (or JSON — YAML is a superset) file.
    ///
    /// Missing fields fall back to their defaults.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read and [`Error::Parse`]
    /// if it is not valid YAML/JSON for this schema.
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let raw = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_owned(),
            source,
        })?;
        serde_yaml::from_str(&raw).map_err(|e| Error::Parse {
            path: path.to_owned(),
            reason: e.to_string(),
        })
    }

    /// Validates cross-field invariants (called by the binary after CLI
    /// overrides are applied).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidGatewayConfig`] when `admin_listen_addr` is
    /// set without a non-empty `admin_secret` — the admin API must never
    /// start unsecured.
    pub fn validate(&self) -> Result<(), Error> {
        if self.admin_listen_addr.is_some()
            && self
                .admin_secret
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
        {
            return Err(Error::InvalidGatewayConfig {
                reason: "`admin_listen_addr` is set but `admin_secret` is missing or empty; \
                         the admin API never runs unsecured"
                    .into(),
            });
        }
        if let Some(guard) = &self.spike_guard {
            if guard.capacity == 0 || guard.refill_per_sec == 0 {
                return Err(Error::InvalidGatewayConfig {
                    reason: "`spike_guard.capacity` and `spike_guard.refill_per_sec` must be \
                             greater than zero (omit `spike_guard` to disable it)"
                        .into(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn defaults_are_sane() {
        let cfg = GatewayConfig::default();
        assert_eq!(cfg.listen_addr.port(), 8080);
        assert_eq!(cfg.apps_dir, PathBuf::from("./apps"));
        assert_eq!(cfg.shutdown_grace_period_secs, 30);
    }

    #[test]
    fn partial_file_fills_defaults() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "listen_addr: \"127.0.0.1:9999\"").expect("write");
        let cfg = GatewayConfig::from_file(f.path()).expect("load");
        assert_eq!(cfg.listen_addr.port(), 9999);
        // Unspecified fields keep their defaults.
        assert_eq!(cfg.shutdown_grace_period_secs, 30);
    }

    #[test]
    fn admin_listener_requires_a_secret() {
        let mut cfg = GatewayConfig::default();
        cfg.validate().expect("no admin config is valid");

        cfg.admin_listen_addr = Some("127.0.0.1:9696".parse().expect("addr"));
        assert!(cfg.validate().is_err(), "listener without secret");

        cfg.admin_secret = Some("  ".into());
        assert!(cfg.validate().is_err(), "blank secret");

        cfg.admin_secret = Some("s3cret".into());
        cfg.validate().expect("listener with secret is valid");

        // A secret alone (no listener) is inert but not an error.
        cfg.admin_listen_addr = None;
        cfg.validate().expect("secret without listener is valid");
    }

    #[test]
    fn spike_guard_fields_must_be_positive() {
        let mut cfg = GatewayConfig {
            spike_guard: Some(SpikeGuardConfig {
                capacity: 0,
                refill_per_sec: 10,
            }),
            ..GatewayConfig::default()
        };
        assert!(cfg.validate().is_err(), "zero capacity");
        cfg.spike_guard = Some(SpikeGuardConfig {
            capacity: 10,
            refill_per_sec: 0,
        });
        assert!(cfg.validate().is_err(), "zero refill");
        cfg.spike_guard = Some(SpikeGuardConfig {
            capacity: 10,
            refill_per_sec: 10,
        });
        cfg.validate().expect("positive fields are valid");
    }

    #[test]
    fn missing_file_is_io_error() {
        let err = GatewayConfig::from_file(Path::new("/nonexistent/g2way.yaml")).unwrap_err();
        assert!(matches!(err, Error::Io { .. }));
    }

    #[test]
    fn malformed_file_is_parse_error() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "listen_addr: [not, an, addr]").expect("write");
        let err = GatewayConfig::from_file(f.path()).unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }
}
