# OAuth2/OIDC auth

The `oidc` auth mode validates bearer tokens issued by an external OpenID
Connect provider (Keycloak, Auth0, Entra ID, …). The gateway is a plain
resource server: it never issues tokens (no gateway-hosted authorization
server) — it discovers the provider's signing
keys, verifies each request's JWT, and optionally maps the token's OAuth2
client id to a stored policy.

## Configuration

```json
{
  "api_id": "payments",
  "name": "Payments",
  "listen_path": "/payments/",
  "target_url": "http://payments.internal:8000",
  "auth": {
    "mode": "oidc",
    "issuer_url": "https://idp.example.com/realms/prod",
    "audiences": ["payments-api"],
    "policy_claim": "azp",
    "policy_map": {
      "mobile-app": "standard",
      "partner-portal": "gold"
    }
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `issuer_url` | (required) | The IdP issuer. Matched **byte-for-byte** against the token's `iss` claim, and the base of the discovery URL. |
| `audiences` | (required, non-empty) | Accepted `aud` values; a token passes if its `aud` intersects this list. |
| `jwks_url` | unset | Direct JWKS URL, skipping discovery — for providers without a standard discovery document. |
| `jwks_refresh_secs` | 300 | Seconds between background key re-fetches. |
| `header` | `Authorization` | Header carrying the token (`Bearer ` prefix stripped). |
| `identity_claim` | `sub` | Claim used as the caller identity (session alias, rate-limit key). |
| `policy_claim` | `azp` | Claim holding the OAuth2 client id for policy mapping. |
| `policy_map` | `{}` | Client id → policy id; see below. |

## Key discovery

Unless `jwks_url` is set, the gateway fetches
`{issuer_url}/.well-known/openid-configuration` (one trailing `/` on the
issuer is trimmed before concatenation), requires the document's `issuer`
to equal the configured `issuer_url` exactly, and reads `jwks_uri` from it.
The resolved `jwks_uri` is then **pinned** for the route's lifetime —
providers do not move it, and any config reload re-discovers.

Keys are cached pod-locally and refreshed in the background every
`jwks_refresh_secs`; a token with an unknown `kid` triggers one immediate
refetch (cooldown-limited). Failed fetches keep the previous key set
(stale-on-error); a successful fetch is authoritative even when it shrinks
the set — that is how key revocation propagates. While the IdP is
unreachable and no keys have ever been fetched (e.g. right after a
gateway boot), token-bearing requests are rejected with the standard 403.

## Token validation

Every request's token must:

- be signed **RS256** by a JWKS key matching its `kid` (tokens without a
  `kid` are rejected; ES256/other algorithms are not yet supported),
- carry `iss` equal to `issuer_url` **byte-for-byte** — a trailing-slash
  mismatch between the config and the token fails closed, per OIDC,
- carry an `aud` intersecting `audiences`,
- carry an unexpired `exp`.

Valid claims become an ephemeral session exactly like the `jwt` mode: alias
and rate-limit identity from `identity_claim` (namespaced `oidc:{identity}`
so it can never collide with stored API keys or `jwt:` identities),
`expires_at` from `exp`, and access to this API only. No storage lookup
happens unless a policy mapping is configured.

## Policy mapping

With a non-empty `policy_map`, the client id read from `policy_claim` must
map to a stored, active [policy](../README.md); the policy's rate, quota,
and ACL then replace the ephemeral session's (so a policy can also revoke
access to this API). Tokens whose client id is missing or unmapped are
rejected — deny-unmatched.

A deliberate design choice: the client id comes from a single
configurable claim (default `azp`), not `aud`/`azp` heuristics. For
RFC 9068 access tokens, set `"policy_claim": "client_id"`.

## Responses

| Status | When |
|---|---|
| `401` | No token in the configured header. |
| `403` | Everything else that is the caller's fault, one indistinguishable message: bad signature, unknown/missing `kid`, wrong or missing `iss`/`aud`/`exp`, expired, wrong algorithm, missing identity claim, unmapped client id, missing/inactive mapped policy, policy not granting this API. Details are logged, never returned. |
| `503` | Storage errored while fetching the mapped policy. |
| `500` | The stored policy record is corrupt. |

## Limits

- RS256 only (the JWKS cache keeps only RSA/RS256 keys today).
- No token introspection (RFC 7662) — validation is purely local.
- The discovery document is fetched with the proxy's shared upstream TLS
  client; a custom CA for the IdP needs the same
  `Forwarder::with_tls_config` hook as any private upstream.
