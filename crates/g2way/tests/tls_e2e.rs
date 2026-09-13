//! End-to-end TLS tests: a real g2way server terminating TLS (and verifying
//! client certificates) in front of a real upstream over TCP.
//!
//! The PKI is minted per test with `rcgen`: a CA, a server certificate for
//! `localhost`, a client certificate signed by the CA, and a "rogue" client
//! certificate from an unrelated CA. No external services are needed.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use g2_core::config::{ClientCertMode, TlsConfig};
use g2_core::session::{cert_fingerprint_hex, hash_key, session_storage_key};
use g2_core::{ApiDefinition, KeySession, DEFAULT_ORG_ID};
use g2_proxy::{Forwarder, Gateway, RouteTable};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Everything a test needs from the freshly minted PKI. The tempdir must
/// stay alive as long as the gateway reads the PEM files.
struct TestPki {
    _dir: tempfile::TempDir,
    cert_file: PathBuf,
    key_file: PathBuf,
    ca_file: PathBuf,
    /// DER of the CA cert — the trust root for test HTTPS clients.
    ca_der: rustls::pki_types::CertificateDer<'static>,
    client_cert: rcgen::Certificate,
    client_key: rcgen::KeyPair,
    rogue_client_cert: rcgen::Certificate,
    rogue_client_key: rcgen::KeyPair,
}

fn mint_pki() -> TestPki {
    let dir = tempfile::tempdir().expect("tempdir");

    let make_ca = |name: &str| {
        let key = rcgen::KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let cert = params.self_signed(&key).expect("ca cert");
        (cert, key)
    };
    let (ca_cert, ca_key) = make_ca("g2way test CA");
    let (rogue_ca_cert, rogue_ca_key) = make_ca("rogue CA");

    let server_key = rcgen::KeyPair::generate().expect("server key");
    let server_cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .expect("server params")
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert");

    let make_client = |name: &str, issuer: &rcgen::Certificate, issuer_key: &rcgen::KeyPair| {
        let key = rcgen::KeyPair::generate().expect("client key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params
            .signed_by(&key, issuer, issuer_key)
            .expect("client cert");
        (cert, key)
    };
    let (client_cert, client_key) = make_client("billing-service", &ca_cert, &ca_key);
    let (rogue_client_cert, rogue_client_key) =
        make_client("intruder", &rogue_ca_cert, &rogue_ca_key);

    let cert_file = dir.path().join("server.pem");
    let key_file = dir.path().join("server-key.pem");
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&cert_file, server_cert.pem()).expect("write server cert");
    std::fs::write(&key_file, server_key.serialize_pem()).expect("write server key");
    std::fs::write(&ca_file, ca_cert.pem()).expect("write ca");

    TestPki {
        _dir: dir,
        cert_file,
        key_file,
        ca_file,
        ca_der: ca_cert.der().clone(),
        client_cert,
        client_key,
        rogue_client_cert,
        rogue_client_key,
    }
}

impl TestPki {
    fn tls_config(&self, mode: ClientCertMode) -> TlsConfig {
        TlsConfig {
            cert_file: Some(self.cert_file.clone()),
            key_file: Some(self.key_file.clone()),
            client_ca_file: (mode != ClientCertMode::None).then(|| self.ca_file.clone()),
            client_cert_mode: mode,
        }
    }

    /// Hex fingerprint of the (good) client certificate — the raw identity
    /// an operator would provision as `mtls:{fingerprint}`.
    fn client_fingerprint(&self) -> String {
        cert_fingerprint_hex(self.client_cert.der().as_ref())
    }

    /// A client config trusting the test CA, optionally presenting a
    /// client certificate.
    fn client_config(
        &self,
        identity: Option<(&rcgen::Certificate, &rcgen::KeyPair)>,
    ) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca_der.clone()).expect("trust test CA");
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots);
        let mut config = match identity {
            None => builder.with_no_client_auth(),
            Some((cert, key)) => builder
                .with_client_auth_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::Pkcs8(key.serialize_der().into()),
                )
                .expect("client identity"),
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
    }
}

/// Spawns an HTTP/1.1 upstream echoing the received `x-forwarded-proto`
/// header back in an `x-echo-proto` response header.
async fn spawn_echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(|req: Request<Incoming>| async move {
                    let proto = req.headers().get("x-forwarded-proto").cloned();
                    let mut resp = Response::new(Full::new(Bytes::from_static(b"ok")));
                    if let Some(proto) = proto {
                        resp.headers_mut().insert("x-echo-proto", proto);
                    }
                    Ok::<_, std::convert::Infallible>(resp)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

/// Starts a TLS-terminating g2way server; returns its address and a
/// shutdown trigger.
async fn spawn_tls_gateway(
    defs: Vec<ApiDefinition>,
    storage: g2_storage::SharedStorage,
    tls_cfg: &TlsConfig,
) -> (SocketAddr, oneshot::Sender<()>) {
    let table = RouteTable::build(defs, &Forwarder::new(), &storage, None, None, None, None)
        .expect("route table");
    let gateway = Arc::new(Gateway::new(table));
    let acceptor = g2way::tls::build_acceptor(tls_cfg).expect("acceptor");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        g2way::server::serve_tls(
            listener,
            gateway,
            acceptor,
            async {
                let _ = rx.await;
            },
            Duration::from_secs(5),
        )
        .await
        .expect("serve_tls");
    });
    (addr, tx)
}

fn api(auth_mode: &str, target: &str) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"tls-e2e","name":"tls e2e","listen_path":"/svc/","target_url":"{target}","auth":{{"mode":"{auth_mode}"}}}}"#
    ))
    .expect("definition")
}

/// Provisions the client certificate's fingerprint as a key session, the
/// way an operator would via `PUT /g2/keys/mtls:{fingerprint}`.
async fn provision_fingerprint(storage: &g2_storage::SharedStorage, fingerprint: &str) {
    let session = KeySession {
        alias: Some("billing-service".into()),
        ..KeySession::default()
    };
    let key = session_storage_key(DEFAULT_ORG_ID, &hash_key(&format!("mtls:{fingerprint}")));
    storage
        .set(&key, &serde_json::to_string(&session).expect("json"), None)
        .await
        .expect("provision");
}

/// One HTTPS request through a fresh TLS connection. Errors (handshake
/// rejections included) are returned, not unwrapped — several tests assert
/// on them.
async fn tls_get(
    addr: SocketAddr,
    config: rustls::ClientConfig,
    path: &str,
) -> Result<(StatusCode, http::HeaderMap), Box<dyn std::error::Error + Send + Sync>> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await?;
    let sni = ServerName::try_from("localhost")?;
    let tls = connector.connect(sni, tcp).await?;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_ref()),
        "server must negotiate the offered ALPN protocol"
    );
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri(path)
        .header(http::header::HOST, "localhost")
        .body(Empty::<Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let headers = resp.headers().clone();
    // Drain the body so the connection can close cleanly.
    let _ = resp.collect().await?;
    Ok((status, headers))
}

fn storage() -> g2_storage::SharedStorage {
    Arc::new(g2_storage::MemoryStorage::new())
}

#[tokio::test]
async fn terminates_tls_and_reports_https_to_the_upstream() {
    let pki = mint_pki();
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_tls_gateway(
        vec![api("keyless", &format!("http://{upstream}"))],
        storage(),
        &pki.tls_config(ClientCertMode::None),
    )
    .await;

    let (status, headers) = tls_get(gw, pki.client_config(None), "/svc/hello")
        .await
        .expect("https request");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("x-echo-proto")
            .expect("proto echoed")
            .as_bytes(),
        b"https",
        "upstream must see x-forwarded-proto: https"
    );
}

#[tokio::test]
async fn mtls_provisioned_cert_is_authorized() {
    let pki = mint_pki();
    let upstream = spawn_echo_upstream().await;
    let store = storage();
    provision_fingerprint(&store, &pki.client_fingerprint()).await;
    let (gw, _stop) = spawn_tls_gateway(
        vec![api("mtls", &format!("http://{upstream}"))],
        store,
        &pki.tls_config(ClientCertMode::Required),
    )
    .await;

    let identity = Some((&pki.client_cert, &pki.client_key));
    let (status, _) = tls_get(gw, pki.client_config(identity), "/svc/hello")
        .await
        .expect("mtls request");
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn mtls_ca_signed_but_unprovisioned_cert_is_403() {
    let pki = mint_pki();
    let upstream = spawn_echo_upstream().await;
    // Storage is empty: the handshake passes, authorization must not.
    let (gw, _stop) = spawn_tls_gateway(
        vec![api("mtls", &format!("http://{upstream}"))],
        storage(),
        &pki.tls_config(ClientCertMode::Required),
    )
    .await;

    let identity = Some((&pki.client_cert, &pki.client_key));
    let (status, _) = tls_get(gw, pki.client_config(identity), "/svc/hello")
        .await
        .expect("handshake passes; rejection is HTTP-level");
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn required_mode_rejects_certificate_less_clients() {
    let pki = mint_pki();
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_tls_gateway(
        vec![api("keyless", &format!("http://{upstream}"))],
        storage(),
        &pki.tls_config(ClientCertMode::Required),
    )
    .await;

    // Where exactly the failure surfaces (connect vs first write) depends
    // on TLS 1.3 timing; assert only that the request cannot succeed.
    let result = tls_get(gw, pki.client_config(None), "/svc/hello").await;
    assert!(result.is_err(), "no client cert must fail in required mode");
}

#[tokio::test]
async fn required_mode_rejects_certs_from_an_unknown_ca() {
    let pki = mint_pki();
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_tls_gateway(
        vec![api("keyless", &format!("http://{upstream}"))],
        storage(),
        &pki.tls_config(ClientCertMode::Required),
    )
    .await;

    let identity = Some((&pki.rogue_client_cert, &pki.rogue_client_key));
    let result = tls_get(gw, pki.client_config(identity), "/svc/hello").await;
    assert!(result.is_err(), "rogue-CA cert must fail the handshake");
}

#[tokio::test]
async fn optional_mode_still_gates_mtls_apis_with_401() {
    let pki = mint_pki();
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_tls_gateway(
        vec![api("mtls", &format!("http://{upstream}"))],
        storage(),
        &pki.tls_config(ClientCertMode::Optional),
    )
    .await;

    let (status, _) = tls_get(gw, pki.client_config(None), "/svc/hello")
        .await
        .expect("optional mode admits the connection");
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn optional_mode_serves_keyless_apis_without_a_cert() {
    let pki = mint_pki();
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_tls_gateway(
        vec![api("keyless", &format!("http://{upstream}"))],
        storage(),
        &pki.tls_config(ClientCertMode::Optional),
    )
    .await;

    let (status, headers) = tls_get(gw, pki.client_config(None), "/svc/hello")
        .await
        .expect("certificate-less request in optional mode");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("x-echo-proto").expect("proto").as_bytes(),
        b"https"
    );
}
