//! Building the TLS acceptor for the proxy listener.
//!
//! This module is the only place the binary touches `rustls` server-side:
//! it turns a validated [`TlsConfig`] into a [`tokio_rustls::TlsAcceptor`]
//! at startup. Certificates are read once — rotation requires a restart
//! (the process config is not hot-reloadable, see ADR-0003). Failures here
//! are startup failures by design: a gateway that cannot load its
//! configured certificates must not come up plaintext instead.

use std::path::Path;
use std::sync::Arc;

use g2_core::config::{ClientCertMode, TlsConfig};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

/// Errors surfaced while building the acceptor (all fatal at startup).
pub type TlsError = Box<dyn std::error::Error + Send + Sync>;

/// How long a client gets to complete the TLS handshake before the
/// connection is dropped. Generous for slow links, short enough that
/// dribbling handshakes cannot pile up.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Builds the listener's TLS acceptor from a validated [`TlsConfig`].
///
/// The server certificate chain and key are loaded from
/// `cert_file`/`key_file`; when `client_cert_mode` is not `none`, client
/// certificates are verified against the `client_ca_file` bundle
/// (`optional` admits certificate-less clients, `required` fails their
/// handshake). ALPN advertises `h2` and `http/1.1` — the accept loop
/// serves both.
///
/// Uses the `ring` crypto provider explicitly, matching the rest of the
/// workspace (the default aws-lc-rs provider needs cmake, which the Docker
/// build stage lacks).
///
/// # Errors
///
/// Returns an error naming the offending file when a PEM file is missing
/// or malformed, when the CA bundle contains no certificates, or when the
/// certificate/key pair is rejected by rustls.
pub fn build_acceptor(cfg: &TlsConfig) -> Result<TlsAcceptor, TlsError> {
    // `GatewayConfig::validate` guarantees both paths are present; a direct
    // caller skipping validation gets a clean error, not a panic.
    let cert_path = cfg
        .cert_file
        .as_deref()
        .ok_or("`tls.cert_file` is not set")?;
    let key_path = cfg.key_file.as_deref().ok_or("`tls.key_file` is not set")?;

    let certs = load_cert_chain(cert_path)?;
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("cannot load `tls.key_file` `{}`: {e}", key_path.display()))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS protocol setup failed: {e}"))?;

    let builder = match cfg.client_cert_mode {
        ClientCertMode::None => builder.with_no_client_auth(),
        mode @ (ClientCertMode::Optional | ClientCertMode::Required) => {
            let ca_path = cfg
                .client_ca_file
                .as_deref()
                .ok_or("`tls.client_ca_file` is not set")?;
            let mut roots = RootCertStore::empty();
            for cert in load_cert_chain(ca_path)? {
                roots.add(cert).map_err(|e| {
                    format!(
                        "`tls.client_ca_file` `{}` holds an unusable CA certificate: {e}",
                        ca_path.display()
                    )
                })?;
            }
            if roots.is_empty() {
                return Err(format!(
                    "`tls.client_ca_file` `{}` contained no certificates",
                    ca_path.display()
                )
                .into());
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
            let verifier = if mode == ClientCertMode::Optional {
                verifier.allow_unauthenticated()
            } else {
                verifier
            };
            let verifier = verifier
                .build()
                .map_err(|e| format!("client certificate verifier setup failed: {e}"))?;
            builder.with_client_cert_verifier(verifier)
        }
    };

    let mut config = builder.with_single_cert(certs, key).map_err(|e| {
        format!(
            "`tls.cert_file` `{}` / `tls.key_file` `{}` rejected: {e}",
            cert_path.display(),
            key_path.display()
        )
    })?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Loads every certificate from a PEM file, erroring with the path on any
/// I/O or parse failure and on an empty file.
fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("cannot read PEM file `{}`: {e}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("malformed certificate in `{}`: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("`{}` contained no certificates", path.display()).into());
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::path::PathBuf;

    /// Writes a self-signed cert + key pair to `dir`, returning the paths.
    fn write_self_signed(dir: &Path) -> (PathBuf, PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
        let cert_path = dir.join("server.pem");
        let key_path = dir.join("server-key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        (cert_path, key_path)
    }

    fn base_config(dir: &Path) -> TlsConfig {
        let (cert_file, key_file) = write_self_signed(dir);
        TlsConfig {
            cert_file: Some(cert_file),
            key_file: Some(key_file),
            ..TlsConfig::default()
        }
    }

    #[test]
    fn builds_from_valid_pem_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        build_acceptor(&base_config(dir.path())).expect("acceptor from valid cert + key");
    }

    #[test]
    fn garbage_pem_errors_name_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = base_config(dir.path());
        let bad = dir.path().join("garbage.pem");
        let mut f = std::fs::File::create(&bad).expect("create");
        writeln!(f, "this is not pem").expect("write");
        cfg.cert_file = Some(bad.clone());
        let Err(err) = build_acceptor(&cfg) else {
            panic!("garbage cert must fail");
        };
        assert!(
            err.to_string().contains("garbage.pem"),
            "error should name the offending file: {err}"
        );
    }

    #[test]
    fn missing_key_file_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = base_config(dir.path());
        cfg.key_file = Some(dir.path().join("nonexistent-key.pem"));
        assert!(build_acceptor(&cfg).is_err());
    }

    #[test]
    fn client_cert_modes_require_a_usable_ca_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Empty-but-existing bundle: hard error, not a silent allow-all.
        let empty_ca = dir.path().join("empty-ca.pem");
        std::fs::write(&empty_ca, "").expect("write empty");
        let mut cfg = base_config(dir.path());
        cfg.client_ca_file = Some(empty_ca);
        cfg.client_cert_mode = ClientCertMode::Required;
        let Err(err) = build_acceptor(&cfg) else {
            panic!("empty CA bundle must fail");
        };
        assert!(
            err.to_string().contains("no certificates"),
            "unexpected error: {err}"
        );

        // A real CA cert works in both client-cert modes.
        let ca = rcgen::generate_simple_self_signed(vec!["g2way test CA".into()]).expect("ca");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca.cert.pem()).expect("write ca");
        for mode in [ClientCertMode::Optional, ClientCertMode::Required] {
            let mut cfg = base_config(dir.path());
            cfg.client_ca_file = Some(ca_path.clone());
            cfg.client_cert_mode = mode;
            build_acceptor(&cfg).expect("acceptor with CA bundle");
        }
    }
}
