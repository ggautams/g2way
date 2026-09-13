# TLS termination & mTLS client certificates

How to run the g2way proxy listener over HTTPS and, optionally, use client
certificates as API credentials. The design decisions behind this feature
are recorded in `docs/adr/0003-tls-termination-and-mtls.md`; this page is
about concepts and operation. TLS is **off by default** — without a `tls`
config block the listener speaks plain HTTP, exactly as before.

## Concepts

**TLS termination** means the gateway itself is the HTTPS endpoint: it
holds the server certificate and private key, performs the TLS handshake
with each client, and decrypts the request before running it through the
middleware chain (auth, rate limiting, caching, …). The encrypted tunnel
*terminates* at the gateway — upstreams keep receiving plain HTTP from it,
with `X-Forwarded-Proto: https` telling them what the client actually
spoke. (The gateway's *upstream-facing* connections are independent of
this: `https://` targets have worked since M7 regardless of how the
listener is configured.)

Why terminate at the gateway rather than in front of it:

- clients reach the gateway directly over HTTPS with no extra
  ingress/nginx hop just for TLS;
- credentials the auth modes read — API keys, JWTs, basic-auth passwords —
  never cross the network in cleartext;
- certificate management stays in one place;
- and it is the prerequisite for mTLS-as-authentication below, which only
  works when the gateway itself sees the handshake.

**Mutual TLS (mTLS)** extends the handshake: the gateway also demands a
certificate *from the client* and verifies it against a CA bundle you
configure. The client proves possession of a private key that never
crosses the wire — a materially stronger machine-to-machine credential
than any bearer token, and one that is checked before a single byte of
HTTP is parsed.

g2way models mTLS as **two independent layers**, and understanding the
split is the key to operating it:

1. **Transport verification** (`tls.client_cert_mode`, process-level):
   does the TLS handshake demand a certificate, and is it signed by your
   CA? A failure here is a failed handshake — the client never gets a
   connection.
2. **Authorization** (`{"auth": {"mode": "mtls"}}`, per-API): is *this
   particular certificate* allowed to call *this API*? The certificate's
   SHA-256 fingerprint is the credential: it must resolve to a provisioned
   key session, exactly like an API key would. A certificate your CA
   signed but nobody provisioned is rejected with `403` — CA membership
   grants a connection, never API access.

Because the fingerprint is provisioned through the ordinary key CRUD, a
certificate gets the **full session model**: its own rate limits, quotas,
expiry, per-API access lists, and policies. Revoking a client is
deprovisioning one key — no CA rotation, no CRLs.

## Configuration reference

| Setting | Purpose | Knob |
|---|---|---|
| Server certificate chain (PEM, leaf first) | enables TLS termination | `tls.cert_file` / `--tls-cert` / `G2_TLS_CERT` |
| Server private key (PEM: PKCS#8, PKCS#1, or SEC1) | enables TLS termination | `tls.key_file` / `--tls-key` / `G2_TLS_KEY` |
| Client-certificate CA bundle (PEM, one or more CAs) | enables mTLS verification | `tls.client_ca_file` / `--tls-client-ca` / `G2_TLS_CLIENT_CA` |
| What the handshake demands from clients | `none` (default) / `optional` / `required` | `tls.client_cert_mode` / `--tls-client-cert-mode` / `G2_TLS_CLIENT_CERT_MODE` |

`client_cert_mode` semantics:

| Mode | Handshake | What `mtls`-auth APIs see |
|---|---|---|
| `none` | client certs neither requested nor accepted | every request is `401` (no certificate can ever be present) |
| `optional` | cert requested; cert-less clients still connect | cert-less requests get `401`; verified certs proceed to authorization. Other APIs (keyless, token, …) work for everyone |
| `required` | handshake **fails** without a CA-signed cert | every request carries a verified cert; authorization decides |

Config-file form (YAML; the same block works in JSON):

```yaml
listen_addr: "0.0.0.0:8443"
tls:
  cert_file: /etc/g2way/tls/server.pem
  key_file: /etc/g2way/tls/server-key.pem
  client_ca_file: /etc/g2way/tls/ca.pem   # only with a non-none mode
  client_cert_mode: required               # none | optional | required
```

Notes:

- Validation is two-stage: `cert_file`+`key_file` must both be present
  whenever a `tls` block exists, a non-`none` `client_cert_mode` requires
  `client_ca_file`, and a `client_ca_file` with mode `none` is rejected as
  dead config — all at config load. The files themselves are read at
  startup; a missing/malformed PEM **fails startup** (the gateway never
  falls back to plaintext).
- ALPN advertises `h2` and `http/1.1`; clients get HTTP/2 or HTTP/1.1
  over the same port.
- Certificates are read **once at startup**. To rotate, restart the
  process (in k8s, roll the pods) — see Limitations.
- The handshake gets 10 seconds before the connection is dropped; slow
  handshakes never stall the accept loop or graceful shutdown.
- The admin listener is unaffected: it stays plain HTTP (keep it
  cluster-internal, as before).

## Generating certificates

A self-signed CA plus one server and one client certificate, with plain
openssl (skip this if you already have a PKI or cert-manager):

```sh
# 1. A CA to anchor trust (clients will --cacert this; the gateway will
#    verify client certs against it).
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout ca-key.pem -out ca.pem -subj "/CN=g2way local CA"

# 2. Server certificate for the gateway. The SAN must match the hostname
#    clients dial (rustls ignores the CN for hostname checks).
openssl req -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server.pem -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# 3. Client certificate (one per calling service).
openssl req -newkey rsa:2048 -nodes \
  -keyout client-key.pem -out client.csr -subj "/CN=billing-service"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
  -out client.pem -days 365 \
  -extfile <(printf "extendedKeyUsage=clientAuth")
```

## Enabling TLS termination

1. Start the gateway with a certificate and key (flags, env vars, or the
   config file — all equivalent):

   ```sh
   g2way --listen 0.0.0.0:8443 \
         --tls-cert server.pem --tls-key server-key.pem \
         --apps-dir examples/apis
   ```

   The startup log confirms it: `TLS termination enabled on the proxy
   listener` and `g2way listening … tls=true`.

2. Call it over HTTPS, trusting your CA:

   ```sh
   curl --cacert ca.pem https://localhost:8443/httpbin/get
   ```

3. Optional sanity checks: `openssl s_client -connect localhost:8443
   -CAfile ca.pem -alpn h2,http/1.1` prints `ALPN protocol: h2`, and the
   upstream now receives `X-Forwarded-Proto: https` (visible in
   httpbin's `/get` echo). A pre-set `X-Forwarded-Proto` from a trusted
   fronting proxy is still preserved, as before.

## Enabling mTLS auth on an API

1. Turn on client-certificate verification at the listener:

   ```sh
   g2way --listen 0.0.0.0:8443 \
         --tls-cert server.pem --tls-key server-key.pem \
         --tls-client-ca ca.pem --tls-client-cert-mode required \
         --admin-listen 127.0.0.1:9696 --admin-secret "$ADMIN_SECRET" \
         --apps-dir ./apis
   ```

   Use `required` when every API on this gateway is certificate-only;
   use `optional` when certificate-clients and token-clients share the
   listener (mTLS APIs still turn cert-less requests away themselves).

2. Put the API in `mtls` mode:

   ```json
   {
     "api_id": "billing",
     "name": "Billing API",
     "listen_path": "/billing/",
     "target_url": "http://billing.internal:8000",
     "auth": { "mode": "mtls" }
   }
   ```

3. Compute the client certificate's fingerprint — the hex SHA-256 of its
   DER encoding:

   ```sh
   openssl x509 -in client.pem -outform DER | sha256sum | cut -d' ' -f1
   # macOS: … | shasum -a 256 | cut -d' ' -f1
   ```

4. Provision it as a key, under the raw key `mtls:{fingerprint}` (the
   `mtls:` namespace keeps certificate identities from ever colliding
   with ordinary API keys — the same trick basic auth uses for
   usernames):

   ```sh
   FP=$(openssl x509 -in client.pem -outform DER | sha256sum | cut -d' ' -f1)
   curl -X PUT "http://127.0.0.1:9696/g2/keys/mtls:$FP" \
     -H "X-G2-Authorization: $ADMIN_SECRET" \
     -H "content-type: application/json" \
     -d '{"alias": "billing-service", "rate": {"requests": 100, "per_seconds": 60}}'
   ```

   Everything a key session can carry works here: `rate`, `quota`,
   `expires_at`, an `access` map restricting which APIs the certificate
   may call, `apply_policies`. Deleting the key
   (`DELETE /g2/keys/mtls:$FP`) revokes the certificate immediately.

5. Call the API with the certificate:

   ```sh
   curl --cacert ca.pem --cert client.pem --key client-key.pem \
     https://localhost:8443/billing/invoices
   ```

Response contract for `mtls` APIs (matching the other auth modes — see
the `g2-middleware` auth rustdoc):

| Status | Meaning |
|---|---|
| handshake failure | `required` mode and the client sent no cert / a cert your CA didn't sign (curl reports e.g. `alert certificate required`) |
| `401` | the connection carries no verified certificate (an `optional`-mode listener, or `mtls` auth configured while the listener has TLS off) |
| `403` | certificate verified but not authorized: fingerprint not provisioned, session inactive/expired, its `access` map doesn't grant this API, or its policy is missing/inactive — one deliberate catch-all message, details in the gateway log |
| `503` | key storage (Redis) unavailable; retryable |

## Kubernetes

The shipped `deploy/k8s/` manifests stay plaintext on purpose — the smoke
test and the default dev loop don't require a PKI. Enabling TLS there is
config, not code:

1. Create Secrets from the PEMs (a `tls`-type Secret for the server pair,
   a generic one for the client CA):

   ```sh
   kubectl -n g2way create secret tls g2way-tls \
     --cert=server.pem --key=server-key.pem
   kubectl -n g2way create secret generic g2way-client-ca \
     --from-file=ca.pem
   ```

2. In `deploy/k8s/gateway.yaml`, mount them and point the `G2_TLS_*` env
   vars at the mounts:

   ```yaml
   env:
     - { name: G2_TLS_CERT,             value: /etc/g2way/tls/tls.crt }
     - { name: G2_TLS_KEY,              value: /etc/g2way/tls/tls.key }
     - { name: G2_TLS_CLIENT_CA,        value: /etc/g2way/client-ca/ca.pem }
     - { name: G2_TLS_CLIENT_CERT_MODE, value: required }
   volumeMounts:
     - { name: tls,       mountPath: /etc/g2way/tls,       readOnly: true }
     - { name: client-ca, mountPath: /etc/g2way/client-ca, readOnly: true }
   volumes:
     - { name: tls,       secret: { secretName: g2way-tls } }
     - { name: client-ca, secret: { secretName: g2way-client-ca } }
   ```

3. Adjust the probes: the liveness/readiness `httpGet` probes hit the
   proxy port, which now speaks HTTPS — set `scheme: HTTPS` on both
   (kubelet probes skip certificate verification, so a self-signed cert
   is fine). The Service needs no change (it forwards TCP), though
   renaming the port `https` is kind to humans.

4. Certificate rotation = updating the Secret and rolling the pods
   (`kubectl -n g2way rollout restart deploy/g2way`); certs are read at
   startup only.

## Limitations

- **No certificate hot-reload.** `tls` lives in the process config, which
  (unlike API definitions) is not hot-reloadable; rotation requires a
  restart. Pods roll gracefully, so this is a non-event in k8s.
- **The admin listener stays plaintext.** It is designed to be
  cluster-internal; front it with something else if it must cross a
  network boundary.
- **One certificate for the listener** — no SNI-based multi-cert serving.
  Put one cert with the SANs you need (or a wildcard) on the listener.
- **No CRL/OCSP checking.** Revocation is deprovisioning the fingerprint
  (`DELETE /g2/keys/mtls:{fp}`), which takes effect immediately and is
  the operationally simpler model.
- **Renewal changes the fingerprint.** A renewed certificate is a new
  credential: provision the new fingerprint alongside the old during
  rollover, then delete the old one.
