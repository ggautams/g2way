//! Per-request context types carried in request extensions.

use std::net::SocketAddr;
use std::sync::Arc;

/// Identity of the API (and owning organization) a request was routed to.
///
/// Built once per route at config-load time and stamped onto every request by
/// [`SetContextLayer`](crate::SetContextLayer); downstream layers read it from
/// request extensions. `Arc<str>` fields make cloning per request cheap.
#[derive(Debug, Clone)]
pub struct RequestContext {
    api_id: Arc<str>,
    org_id: Arc<str>,
}

impl RequestContext {
    /// Creates a context for the given API and organization ids.
    #[must_use]
    pub fn new(api_id: impl Into<Arc<str>>, org_id: impl Into<Arc<str>>) -> Self {
        Self {
            api_id: api_id.into(),
            org_id: org_id.into(),
        }
    }

    /// The `api_id` of the matched API definition.
    #[must_use]
    pub fn api_id(&self) -> &str {
        &self.api_id
    }

    /// The id of the organization owning the matched API.
    #[must_use]
    pub fn org_id(&self) -> &str {
        &self.org_id
    }
}

/// The authenticated key session of a request.
///
/// Inserted into request extensions by the auth layer after a credential
/// resolves to a live [`KeySession`](g2_core::KeySession); downstream layers (rate limiting,
/// quotas, analytics) read it back. Keyless APIs carry no `SessionContext`.
#[derive(Debug, Clone)]
pub struct SessionContext {
    session: Arc<g2_core::KeySession>,
    key_hash: Arc<str>,
}

impl SessionContext {
    /// Wraps a resolved session and the (hashed) key it was looked up under.
    #[must_use]
    pub fn new(session: g2_core::KeySession, key_hash: impl Into<Arc<str>>) -> Self {
        Self {
            session: Arc::new(session),
            key_hash: key_hash.into(),
        }
    }

    /// The resolved key session.
    #[must_use]
    pub fn session(&self) -> &g2_core::KeySession {
        &self.session
    }

    /// SHA-256 hex digest identifying the key (never the raw credential).
    #[must_use]
    pub fn key_hash(&self) -> &str {
        &self.key_hash
    }
}

/// Marker: this request's path matched an `ignore_auth_paths` rule.
///
/// Inserted into request extensions by the path-policy layer (which runs
/// above auth); the auth layer sees it and forwards the request without
/// authenticating — so no [`SessionContext`] is stamped, and the rate-limit
/// layer (which needs a session) passes it through too. Never derived from
/// anything a client sends: extensions only ever come from gateway layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthBypass;

/// Time one request spent on its upstream round trip.
///
/// Inserted into **response** extensions by the forwarding service (on
/// success and on 502/504 alike), so outer layers — which never see the
/// request extensions stamped below them — can attribute latency. Requests
/// rejected before the forwarder carry no `UpstreamLatency`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamLatency(pub std::time::Duration);

/// The remote (client) socket address of a request.
///
/// Inserted into request extensions by the gateway before the chain runs,
/// because only the accept loop knows the peer address; the forwarding
/// service reads it to extend `X-Forwarded-For`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr(pub SocketAddr);

/// Transport-level facts about the connection a request arrived on.
///
/// Built once per connection by the accept loop (which is the only place
/// that knows whether TLS was terminated and what the handshake verified)
/// and stamped onto every request by the gateway, next to [`ClientAddr`].
/// The forwarding service reads `tls` for `X-Forwarded-Proto`; the auth
/// layer's `mtls` mode reads `client_cert_fingerprint`. Plain data only —
/// this crate stays TLS-library-free.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// True when the gateway terminated TLS on this connection.
    pub tls: bool,

    /// Hex SHA-256 fingerprint of the client certificate's DER encoding,
    /// when the handshake verified one (see
    /// [`g2_core::session::cert_fingerprint_hex`]). Always `None` on
    /// plaintext connections; `None` under `client_cert_mode: optional`
    /// when the client presented no certificate. Never derived from
    /// anything a client sends inside the request.
    pub client_cert_fingerprint: Option<Arc<str>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_exposes_ids() {
        let ctx = RequestContext::new("users-api", "acme");
        assert_eq!(ctx.api_id(), "users-api");
        assert_eq!(ctx.org_id(), "acme");
    }

    #[test]
    fn context_clones_share_backing_storage() {
        let ctx = RequestContext::new("a", "o");
        let clone = ctx.clone();
        assert!(std::ptr::eq(ctx.api_id(), clone.api_id()));
    }
}
