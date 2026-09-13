# ADR-0003: TLS termination and mTLS client certificates

Date: 2026-08-31 · Status: accepted

## Context

Through M7 the proxy listener spoke only plain HTTP; anything encrypted
had to be terminated in front of the gateway, and mTLS-as-authentication
was impossible (the gateway never saw the handshake). M8 adds inbound TLS:
the listener terminates HTTPS itself and can demand CA-verified client
certificates, with a per-API `mtls` auth mode mapping certificates to key
sessions. Operational guidance lives in `docs/tls.md`.

## Decisions

1. **The acceptor lives in the `g2way` binary crate.** `g2way::tls`
   builds a `tokio_rustls::TlsAcceptor` from the config at startup;
   `g2-proxy` and `g2-middleware` stay TLS-library-free. Transport facts
   cross into the chain as one plain-data request extension
   (`ConnectionInfo { tls, client_cert_fingerprint }`), stamped by
   `Gateway::handle` next to `ClientAddr` — the same inversion that keeps
   the JWKS HTTP client behind a trait. Considered: an acceptor inside
   `g2-proxy` (drags rustls into every consumer of the proxy crate).

2. **`ring` crypto provider, selected explicitly.** Server configs are
   built with `builder_with_provider(ring)` rather than the process
   default — no global `install_default()`, no ambiguity if a second
   provider feature ever appears. Same rationale as M7: aws-lc-rs needs
   cmake, which the `rust:1-slim` Docker build stage lacks.

3. **ALPN `h2` + `http/1.1`**, with hyper-util's auto builder serving
   whichever the handshake negotiated — one port, both protocols, same as
   the plaintext listener's autodetection.

4. **Certificate fingerprint as the mTLS credential** (a static-mTLS
   model). The hex SHA-256 of the verified leaf cert's DER resolves —
   hashed, under an `mtls:` namespace like basic auth's usernames — to a
   stored `KeySession`, provisioned via the ordinary admin key CRUD as
   the raw key `mtls:{fingerprint}` (zero admin-API changes). This buys
   per-certificate rate/quota/ACL/policy for free and makes revocation a
   key deletion. Transport verification (CA signature) and authorization
   (fingerprint provisioned) are deliberately separate layers: a CA-signed
   but unprovisioned cert gets `403`. Considered: subject-DN mapping
   (parsing x509 adds a dependency and DNs are forgeable across CAs
   in multi-CA bundles), ephemeral JWT-style sessions for any CA-signed
   cert (no per-client limits, revocation requires CA rotation).

5. **Handshake on the connection's task, not the accept loop.** The
   accept loop only accepts; each connection's task runs the TLS
   handshake under a 10s timeout, then serves. Graceful shutdown uses
   `GracefulShutdown::watcher()` clones taken at accept time, so drained
   connections are exactly the post-handshake ones — a client dribbling
   its handshake can never stall shutdown (it dies when the grace period
   expires).

6. **TLS is process config and therefore not hot-reloadable.** Only the
   route table swaps via ArcSwap; certificates are read once at startup
   and rotation is a restart (a pod roll in k8s). A `ResolvesServerCert`
   hot-reload can be added later without config changes if it earns its
   keep.

7. **Out of scope, recorded as limitations:** the admin listener stays
   plaintext (cluster-internal by design), no SNI multi-cert, no
   CRL/OCSP (revocation = deprovisioning the fingerprint). The shipped
   k8s manifests stay plaintext; `docs/tls.md` documents enabling TLS
   there via Secrets and `G2_TLS_*` env vars.

## Consequences

- `x-forwarded-proto` is now truthful: the rewrite layer reads
  `ConnectionInfo.tls` instead of hardcoding `http`.
- `Gateway::handle` takes the per-connection `ConnectionInfo` as a
  parameter; plaintext callers pass `ConnectionInfo::default()`.
- `g2way` gains real `rustls`/`tokio-rustls` dependencies (ring-only,
  matching the workspace pins); e2e tests mint throwaway PKIs with rcgen
  and run without external services.
- A renewed client certificate is a new credential (new fingerprint);
  rollover means provisioning both for the overlap window.
