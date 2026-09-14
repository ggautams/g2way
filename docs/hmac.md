# HMAC request-signature auth

The `hmac` auth mode verifies draft-cavage HTTP Signatures: each request
carries an `Authorization: Signature …` header
whose signature covers the request line and selected headers, computed with
a shared secret provisioned per key. Unlike bearer tokens, the credential
never travels on the wire and each signature is bound to the request it
signs (and, with the default clock-skew check, to a time window).

## Configuration

```json
{
  "api_id": "ledger",
  "name": "Ledger",
  "listen_path": "/ledger/",
  "target_url": "http://ledger.internal:8000",
  "auth": {
    "mode": "hmac",
    "allowed_algorithms": ["hmac-sha256"],
    "allowed_clock_skew_secs": 300
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `allowed_algorithms` | all three | Accepted `algorithm` values: `hmac-sha256`, `hmac-sha384`, `hmac-sha512`. `hmac-sha1` is deliberately unsupported (a hardening choice). |
| `allowed_clock_skew_secs` | `300` | Maximum seconds the request's `Date` header may differ from the gateway clock. An explicit `null` disables the check; `0` is rejected. While enabled, `date` must be among the signed headers — an unsigned `Date` is attacker-controlled, so bounding it would prove nothing. |

Credentials are read from the `Authorization` header only (where the
`Signature` scheme lives; there is no `header` knob, matching basic auth).

## Provisioning keys

The `keyId` resolves — hashed, under an `hmac:` namespace like basic auth's
`basic:{username}` and mTLS's `mtls:{fingerprint}` — to an ordinary stored
session, provisioned through the standard key CRUD:

```sh
curl -H "X-G2-Authorization: $ADMIN_SECRET" -X PUT \
  http://gateway:9696/g2/keys/hmac:mykey \
  -d '{"alias": "billing-batch", "hmac": {"secret": "the-shared-secret"}, "access": {"ledger": {}}}'
```

Sessions get full key semantics: rate, quota, expiry, ACL, and policies all
apply. Two caveats:

- The secret is HMAC'd as its **raw UTF-8 bytes** (ordinary client snippets
  work verbatim); arbitrary binary secrets are not supported.
- Unlike a bcrypt password hash, the secret is a live credential stored **in
  plaintext** in the session record — HMAC verification needs the secret
  itself, and the admin `GET /g2/keys/…`
  endpoints return it. (Redacting it on read is a possible follow-up.)

## Signing a request

The header carries four parameters (`headers` is optional and defaults to
`date`; unknown parameters are ignored, duplicates rejected):

```
Authorization: Signature keyId="mykey",algorithm="hmac-sha256",headers="(request-target) date",signature="base64…"
```

The signing string is one line per name in `headers` (lowercased), joined
with `\n`, no trailing newline:

- `(request-target)` → the lowercased method, a space, and the path plus
  query **exactly as sent to the gateway** — the listen path included, since
  auth runs before any path stripping or rewriting. This is the classic
  integration gotcha: sign `/ledger/x`,
  not `/x`.
- any other name → `name: value` (lowercased name); multiple values of the
  same header are joined with `", "`. A named header absent from the request
  is a 403.

Worked example (a percent-encoded signature is also accepted):

```sh
DATE="$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S GMT')"
SIGNING_STRING="get /ledger/x
date: ${DATE}"
SIG=$(printf '%s' "$SIGNING_STRING" \
  | openssl dgst -sha256 -hmac "the-shared-secret" -binary | base64)
curl http://gateway:8080/ledger/x -H "Date: ${DATE}" \
  -H "Authorization: Signature keyId=\"mykey\",algorithm=\"hmac-sha256\",headers=\"(request-target) date\",signature=\"${SIG}\""
```

## Responses

| Status | When |
|---|---|
| `401` | No parseable `Signature` credential: missing `Authorization`, wrong scheme, malformed parameter list, missing required parameter, undecodable base64. |
| `403` | Everything else that is the caller's fault, one indistinguishable message: unknown `keyId`, session without hmac data, bad signature, disallowed algorithm, a signed header absent from the request, `Date` missing/unparseable/outside the allowed skew, session inactive/expired/not granting this API, policy missing or inactive. Details are logged, never returned. Unknown keyIds still cost one HMAC against a dummy secret (no key-enumeration timing oracle), and signature comparison is constant-time. |
| `503` | Storage errored during the key or policy lookup. |
| `500` | The stored session or policy record is corrupt. |

## Limits

- SHA-2 HMACs only: no `hmac-sha1`, and no RSA signatures (draft-cavage
  `rsa-sha256` would be its own follow-up).
- No `(created)`/`(expires)` pseudo-headers from later HTTP-Signature
  drafts (they fall out as "missing header" → 403); freshness comes from
  the signed `Date` plus `allowed_clock_skew_secs`.
- Signing a `digest` header only proves the header was signed — the gateway
  never hashes the body to check it (body-digest checking is not
  implemented).
