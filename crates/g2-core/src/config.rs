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

/// Which sink per-request analytics records are delivered to.
///
/// The sinks themselves live in `g2-telemetry`; this is only the
/// configuration vocabulary. Absent from the config means analytics
/// records are not produced at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalyticsSinkKind {
    /// One JSON record per line on stdout (interleaves cleanly with the
    /// gateway's line-delimited JSON logs).
    Stdout,
    /// Records appended to a capped Redis list (`g2:{org}:analytics:records`)
    /// for an external pump to drain. Requires `redis_url`.
    Redis,
    /// Records exported as OTLP log records to `{otlp_endpoint}/v1/logs`.
    /// Requires `otlp_endpoint`.
    OtlpLogs,
}

/// Error returned when parsing an [`AnalyticsSinkKind`] from a string fails.
#[derive(Debug, thiserror::Error)]
#[error("unknown analytics sink `{0}`; expected `stdout`, `redis`, or `otlp_logs`")]
pub struct ParseAnalyticsSinkError(String);

impl std::str::FromStr for AnalyticsSinkKind {
    type Err = ParseAnalyticsSinkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "stdout" => Ok(Self::Stdout),
            "redis" => Ok(Self::Redis),
            "otlp_logs" | "otlp-logs" => Ok(Self::OtlpLogs),
            other => Err(ParseAnalyticsSinkError(other.to_owned())),
        }
    }
}

/// How the TLS listener treats client certificates (mTLS).
///
/// This is the **transport-level** knob: it decides what the TLS handshake
/// demands. Whether a presented certificate is *authorized* is a separate,
/// per-API decision made by the `mtls` auth mode (see `docs/tls.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientCertMode {
    /// Client certificates are neither requested nor accepted (plain TLS
    /// termination). The default.
    #[default]
    None,
    /// Clients are asked for a certificate; connections without one are
    /// still accepted. APIs in `mtls` auth mode then reject certificate-less
    /// requests with `401` while other APIs keep working.
    Optional,
    /// The handshake fails unless the client presents a certificate signed
    /// by the configured `client_ca_file` bundle.
    Required,
}

/// Error returned when parsing a [`ClientCertMode`] from a string fails.
#[derive(Debug, thiserror::Error)]
#[error("unknown client cert mode `{0}`; expected `none`, `optional`, or `required`")]
pub struct ParseClientCertModeError(String);

impl std::str::FromStr for ClientCertMode {
    type Err = ParseClientCertModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            other => Err(ParseClientCertModeError(other.to_owned())),
        }
    }
}

/// TLS termination settings for the proxy listener.
///
/// Absent from the config means the listener speaks plain HTTP. When
/// present, `cert_file` and `key_file` are both required; the certificate
/// files are read once at startup (rotation requires a restart — the
/// process config is not hot-reloadable, see ADR-0003).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// PEM file holding the server certificate chain, leaf first.
    pub cert_file: Option<PathBuf>,

    /// PEM file holding the server private key (PKCS#8, PKCS#1, or SEC1).
    pub key_file: Option<PathBuf>,

    /// PEM bundle of CA certificates client certificates are verified
    /// against. Required when `client_cert_mode` is not `none`; setting it
    /// while `client_cert_mode` is `none` is a config error (it would be
    /// silently ignored otherwise).
    pub client_ca_file: Option<PathBuf>,

    /// What the handshake demands from clients (see [`ClientCertMode`]).
    pub client_cert_mode: ClientCertMode,
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

    /// Base endpoint of an OTLP/HTTP collector for trace export, e.g.
    /// `http://otel-collector:4318` (the `/v1/traces` signal path is
    /// appended automatically). `None` — the default — disables OTLP
    /// export; per-request spans then only enrich the process logs.
    pub otlp_endpoint: Option<String>,

    /// Where per-request analytics records are delivered. `None` — the
    /// default — disables analytics records entirely (the observability
    /// spans/metrics knobs above are independent of this).
    pub analytics_sink: Option<AnalyticsSinkKind>,

    /// TLS termination for the proxy listener. `None` — the default — means
    /// the listener speaks plain HTTP (see [`TlsConfig`] and `docs/tls.md`).
    pub tls: Option<TlsConfig>,
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
            otlp_endpoint: None,
            analytics_sink: None,
            tls: None,
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
        if let Some(endpoint) = &self.otlp_endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(Error::InvalidGatewayConfig {
                    reason: format!(
                        "`otlp_endpoint` must be an http:// or https:// URL, got `{endpoint}` \
                         (omit it to disable OTLP export)"
                    ),
                });
            }
        }
        match self.analytics_sink {
            Some(AnalyticsSinkKind::Redis) if self.redis_url.is_none() => {
                return Err(Error::InvalidGatewayConfig {
                    reason: "`analytics_sink: redis` requires `redis_url` — with in-memory \
                             storage the records would pile up unread in this process"
                        .into(),
                });
            }
            Some(AnalyticsSinkKind::OtlpLogs) if self.otlp_endpoint.is_none() => {
                return Err(Error::InvalidGatewayConfig {
                    reason: "`analytics_sink: otlp_logs` requires `otlp_endpoint` — there is \
                             no collector to export the records to"
                        .into(),
                });
            }
            _ => {}
        }
        if let Some(tls) = &self.tls {
            if tls.cert_file.is_none() || tls.key_file.is_none() {
                return Err(Error::InvalidGatewayConfig {
                    reason: "`tls` requires both `tls.cert_file` and `tls.key_file` (omit the \
                             `tls` block entirely for a plain-HTTP listener)"
                        .into(),
                });
            }
            if tls.client_cert_mode != ClientCertMode::None && tls.client_ca_file.is_none() {
                return Err(Error::InvalidGatewayConfig {
                    reason: format!(
                        "`tls.client_cert_mode: {}` requires `tls.client_ca_file` — there is \
                         no CA to verify client certificates against",
                        if tls.client_cert_mode == ClientCertMode::Optional {
                            "optional"
                        } else {
                            "required"
                        }
                    ),
                });
            }
            if tls.client_cert_mode == ClientCertMode::None && tls.client_ca_file.is_some() {
                return Err(Error::InvalidGatewayConfig {
                    reason: "`tls.client_ca_file` is set but `tls.client_cert_mode` is `none`; \
                             the bundle would be silently ignored — set the mode to `optional` \
                             or `required`, or drop the bundle"
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
    fn otlp_endpoint_must_be_an_http_url() {
        let mut cfg = GatewayConfig {
            otlp_endpoint: Some("otel-collector:4318".into()),
            ..GatewayConfig::default()
        };
        assert!(cfg.validate().is_err(), "scheme-less endpoint");
        cfg.otlp_endpoint = Some("http://otel-collector:4318".into());
        cfg.validate().expect("http endpoint is valid");
        cfg.otlp_endpoint = Some("https://collector.example.com".into());
        cfg.validate().expect("https endpoint is valid");
    }

    #[test]
    fn analytics_sink_kind_parses_and_serializes() {
        assert_eq!(
            "stdout".parse::<AnalyticsSinkKind>().expect("stdout"),
            AnalyticsSinkKind::Stdout
        );
        assert_eq!(
            "otlp-logs".parse::<AnalyticsSinkKind>().expect("hyphens"),
            AnalyticsSinkKind::OtlpLogs
        );
        assert!("syslog".parse::<AnalyticsSinkKind>().is_err());
        // The serde form matches the FromStr form (config file vs CLI).
        assert_eq!(
            serde_yaml::to_string(&AnalyticsSinkKind::OtlpLogs).expect("yaml"),
            "otlp_logs\n"
        );
    }

    #[test]
    fn analytics_sinks_require_their_backends() {
        let mut cfg = GatewayConfig {
            analytics_sink: Some(AnalyticsSinkKind::Redis),
            ..GatewayConfig::default()
        };
        assert!(cfg.validate().is_err(), "redis sink without redis_url");
        cfg.redis_url = Some("redis://localhost:6379/".into());
        cfg.validate().expect("redis sink with redis_url");

        cfg.analytics_sink = Some(AnalyticsSinkKind::OtlpLogs);
        assert!(cfg.validate().is_err(), "otlp sink without endpoint");
        cfg.otlp_endpoint = Some("http://collector:4318".into());
        cfg.validate().expect("otlp sink with endpoint");

        cfg.analytics_sink = Some(AnalyticsSinkKind::Stdout);
        cfg.redis_url = None;
        cfg.otlp_endpoint = None;
        cfg.validate().expect("stdout sink needs nothing");
    }

    #[test]
    fn tls_block_requires_cert_and_key() {
        let mut cfg = GatewayConfig {
            tls: Some(TlsConfig::default()),
            ..GatewayConfig::default()
        };
        assert!(cfg.validate().is_err(), "empty tls block");

        cfg.tls = Some(TlsConfig {
            cert_file: Some("server.pem".into()),
            ..TlsConfig::default()
        });
        assert!(cfg.validate().is_err(), "cert without key");

        cfg.tls = Some(TlsConfig {
            cert_file: Some("server.pem".into()),
            key_file: Some("server-key.pem".into()),
            ..TlsConfig::default()
        });
        cfg.validate().expect("cert + key is valid");
    }

    #[test]
    fn client_cert_mode_and_ca_bundle_must_agree() {
        let base = TlsConfig {
            cert_file: Some("server.pem".into()),
            key_file: Some("server-key.pem".into()),
            ..TlsConfig::default()
        };

        let mut cfg = GatewayConfig {
            tls: Some(TlsConfig {
                client_cert_mode: ClientCertMode::Required,
                ..base.clone()
            }),
            ..GatewayConfig::default()
        };
        assert!(cfg.validate().is_err(), "required mode without a CA bundle");

        cfg.tls = Some(TlsConfig {
            client_ca_file: Some("ca.pem".into()),
            ..base.clone()
        });
        assert!(
            cfg.validate().is_err(),
            "CA bundle with mode none is dead config"
        );

        for mode in [ClientCertMode::Optional, ClientCertMode::Required] {
            cfg.tls = Some(TlsConfig {
                client_ca_file: Some("ca.pem".into()),
                client_cert_mode: mode,
                ..base.clone()
            });
            cfg.validate()
                .expect("CA bundle with a non-none mode is valid");
        }
    }

    #[test]
    fn tls_block_round_trips_through_yaml() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            f,
            "tls:\n  cert_file: server.pem\n  key_file: server-key.pem\n  \
             client_ca_file: ca.pem\n  client_cert_mode: required"
        )
        .expect("write");
        let cfg = GatewayConfig::from_file(f.path()).expect("load");
        let tls = cfg.tls.expect("tls block parsed");
        assert_eq!(tls.cert_file.as_deref(), Some(Path::new("server.pem")));
        assert_eq!(tls.key_file.as_deref(), Some(Path::new("server-key.pem")));
        assert_eq!(tls.client_ca_file.as_deref(), Some(Path::new("ca.pem")));
        assert_eq!(tls.client_cert_mode, ClientCertMode::Required);
        // Absent block stays None and validates.
        assert_eq!(GatewayConfig::default().tls, None);
    }

    #[test]
    fn client_cert_mode_parses_and_serializes() {
        assert_eq!(
            "required".parse::<ClientCertMode>().expect("required"),
            ClientCertMode::Required
        );
        assert_eq!(
            "None".parse::<ClientCertMode>().expect("case-insensitive"),
            ClientCertMode::None
        );
        assert!("mandatory".parse::<ClientCertMode>().is_err());
        // The serde form matches the FromStr form (config file vs CLI).
        assert_eq!(
            serde_yaml::to_string(&ClientCertMode::Optional).expect("yaml"),
            "optional\n"
        );
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
