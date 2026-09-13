//! [`IpFilterLayer`]: per-API client-IP allow/deny lists.
//!
//! Sits directly below [`SetContextLayer`](crate::SetContextLayer), above
//! every other policy layer: a blocked client gets nothing — no CORS
//! headers, no path evaluation, no credential work.
//!
//! The address checked is the **socket peer address** ([`ClientAddr`],
//! stamped by the gateway's accept loop) — never client-supplied headers
//! like `X-Forwarded-For`, which anyone can spoof. Deployments behind an
//! L7 load balancer therefore see the balancer's address; trusted-proxy
//! support is a deliberate non-goal until it is needed.
//!
//! Semantics mirror the path lists: `block_ips` wins unconditionally, and a
//! non-empty `allow_ips` makes the API allow-list-only. Both rejections
//! share one `403` message. IPv4-mapped IPv6 peers (`::ffff:10.0.0.1` on
//! dual-stack listeners) are canonicalized before matching, so IPv4 rules
//! match them.

use std::convert::Infallible;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use g2_core::security::parse_ip_entry;
use g2_core::Error;
use http::{Request, Response, StatusCode};
use ipnet::IpNet;
use tower::{Layer, Service};

use crate::context::ClientAddr;
use crate::response::json_error;
use crate::ProxyBody;

/// One 403 message for blocked and not-allow-listed clients alike; which
/// list rejected a request must not leak to the caller.
const FORBIDDEN_IP_MSG: &str = "access from this address is forbidden";

/// One API's parsed IP lists, shared by every clone of the service.
#[derive(Debug)]
struct FilterState {
    allow: Vec<IpNet>,
    block: Vec<IpNet>,
}

/// Tower layer enforcing one API's client-IP allow/deny lists.
#[derive(Debug, Clone)]
pub struct IpFilterLayer {
    state: Arc<FilterState>,
}

impl IpFilterLayer {
    /// Parses the two lists into a layer, or `None` when both are empty
    /// (the API gets no filter layer at all); `api_id` names the API in
    /// errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when an entry is neither an
    /// IP address nor a CIDR network. Definitions are validated before
    /// routes are built, so this failing indicates a validation gap, but
    /// the route build surfaces it loudly rather than panicking.
    pub fn from_config(
        allow: &[String],
        block: &[String],
        api_id: &str,
    ) -> Result<Option<Self>, Error> {
        if allow.is_empty() && block.is_empty() {
            return Ok(None);
        }
        let parse_list = |list: &[String], field: &str| {
            list.iter()
                .map(|entry| {
                    parse_ip_entry(entry).ok_or_else(|| Error::InvalidApiDefinition {
                        api: api_id.to_owned(),
                        reason: format!("`{field}` entry is not an IP or CIDR: `{entry}`"),
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Some(Self {
            state: Arc::new(FilterState {
                allow: parse_list(allow, "allow_ips")?,
                block: parse_list(block, "block_ips")?,
            }),
        }))
    }
}

impl<S> Layer<S> for IpFilterLayer {
    type Service = IpFilter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IpFilter {
            inner,
            state: Arc::clone(&self.state),
        }
    }
}

/// The [`Service`] produced by [`IpFilterLayer`].
#[derive(Debug, Clone)]
pub struct IpFilter<S> {
    inner: S,
    state: Arc<FilterState>,
}

impl<S> IpFilter<S> {
    /// Whether `ip` may use this API.
    fn permits(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        if self.state.block.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        self.state.allow.is_empty() || self.state.allow.iter().any(|net| net.contains(&ip))
    }
}

impl<S> Service<Request<ProxyBody>> for IpFilter<S>
where
    S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ProxyBody>) -> Self::Future {
        // The gateway stamps ClientAddr on every request before the chain
        // runs. A missing address means a wiring bug — fail closed: an IP
        // filter that cannot see the IP must not wave traffic through.
        let permitted = match req.extensions().get::<ClientAddr>() {
            Some(addr) => self.permits(addr.0.ip()),
            None => {
                tracing::error!("IP filter found no ClientAddr on the request; rejecting");
                false
            }
        };
        if !permitted {
            return Box::pin(std::future::ready(Ok(json_error(
                StatusCode::FORBIDDEN,
                FORBIDDEN_IP_MSG,
            ))));
        }
        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bytes::Bytes;
    use http_body_util::Full;
    use tower::ServiceExt;

    use super::*;

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    async fn ok(_req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        Ok(Response::new(body()))
    }

    fn layer(allow: &[&str], block: &[&str]) -> IpFilterLayer {
        let list = |entries: &[&str]| entries.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>();
        IpFilterLayer::from_config(&list(allow), &list(block), "api")
            .expect("parses")
            .expect("non-empty config")
    }

    async fn call(layer: &IpFilterLayer, peer: Option<&str>) -> StatusCode {
        let mut req = Request::new(body());
        if let Some(peer) = peer {
            let addr: SocketAddr = format!("{peer}:9999")
                .parse()
                .or_else(|_| format!("[{peer}]:9999").parse())
                .expect("peer addr");
            req.extensions_mut().insert(ClientAddr(addr));
        }
        layer
            .layer(tower::service_fn(ok))
            .oneshot(req)
            .await
            .expect("infallible")
            .status()
    }

    #[test]
    fn empty_config_builds_no_layer() {
        assert!(IpFilterLayer::from_config(&[], &[], "api")
            .expect("ok")
            .is_none());
    }

    #[test]
    fn invalid_entries_fail_compilation() {
        assert!(IpFilterLayer::from_config(&["nope".into()], &[], "api").is_err());
    }

    #[tokio::test]
    async fn block_list_rejects_addresses_and_networks() {
        let layer = layer(&[], &["10.1.2.3", "192.168.0.0/16"]);
        assert_eq!(call(&layer, Some("10.1.2.3")).await, StatusCode::FORBIDDEN);
        assert_eq!(
            call(&layer, Some("192.168.44.5")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(call(&layer, Some("10.1.2.4")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn allow_list_makes_the_api_allow_list_only() {
        let layer = layer(&["10.0.0.0/8"], &[]);
        assert_eq!(call(&layer, Some("10.200.1.1")).await, StatusCode::OK);
        assert_eq!(call(&layer, Some("11.0.0.1")).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn block_wins_over_allow() {
        let layer = layer(&["10.0.0.0/8"], &["10.0.0.5"]);
        assert_eq!(call(&layer, Some("10.0.0.5")).await, StatusCode::FORBIDDEN);
        assert_eq!(call(&layer, Some("10.0.0.6")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_peers_match_ipv4_rules() {
        let layer = layer(&["10.0.0.0/8"], &[]);
        assert_eq!(call(&layer, Some("::ffff:10.0.0.1")).await, StatusCode::OK);
        assert_eq!(
            call(&layer, Some("::ffff:11.0.0.1")).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn ipv6_rules_match_ipv6_peers() {
        let layer = layer(&[], &["2001:db8::/32"]);
        assert_eq!(
            call(&layer, Some("2001:db8::1")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(call(&layer, Some("2001:db9::1")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_client_addr_fails_closed() {
        let layer = layer(&["0.0.0.0/0"], &[]);
        assert_eq!(call(&layer, None).await, StatusCode::FORBIDDEN);
    }
}
