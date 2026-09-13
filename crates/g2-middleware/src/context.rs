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
