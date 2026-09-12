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
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            apps_dir: default_apps_dir(),
            shutdown_grace_period_secs: 30,
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
