//! The [`Gateway`]: per-request entry point tying routing, rewriting, and
//! upstream forwarding together.

use std::net::SocketAddr;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::uri::Uri;
use http::{header, HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::rewrite;
use crate::router::RouteTable;

/// Boxed error type used for proxied body streams.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The response body type produced by the gateway: either a locally
/// generated body (errors, health checks) or the streamed upstream body.
pub type ProxyBody = BoxBody<Bytes, BoxError>;

/// Gateway version reported by `/hello` (the workspace version).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The proxy engine shared by all connections of a gateway process.
///
/// Generic over the request body `B` so production code uses hyper's
/// streaming [`Incoming`] while tests inject synthetic bodies. The route
/// table lives in an [`ArcSwap`]: requests load it wait-free, and
/// [`Gateway::reload`] swaps in a new table atomically.
pub struct Gateway<B = Incoming> {
    table: ArcSwap<RouteTable>,
    client: Client<HttpConnector, B>,
}

impl<B> Gateway<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Creates a gateway serving `table` with a default pooled HTTP client.
    #[must_use]
    pub fn new(table: RouteTable) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            table: ArcSwap::from_pointee(table),
            client,
        }
    }

    /// Atomically replaces the routing table (config hot reload).
    pub fn reload(&self, table: RouteTable) {
        self.table.store(std::sync::Arc::new(table));
    }

    /// Number of active routes currently loaded (for logs and status APIs).
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.table.load().routes().len()
    }

    /// Handles one client request end to end.
    ///
    /// Never returns an error: every failure is mapped to an HTTP error
    /// response (`404` no matching API, `502` upstream unreachable, `504`
    /// upstream timeout).
    pub async fn handle(&self, req: Request<B>, remote_addr: SocketAddr) -> Response<ProxyBody> {
        let path = req.uri().path();

        // Health endpoints are served before routing so an API mounted on `/`
        // cannot shadow them.
        if path == "/hello" || path == "/ready" {
            return health_response();
        }

        let table = self.table.load();
        let Some(route) = table.match_path(path) else {
            tracing::debug!(path, "no API matched");
            return error_response(StatusCode::NOT_FOUND, "no API found for path");
        };
        let route = route.clone();
        drop(table);

        let api_id = route.def.api_id.clone();
        let timeout = Duration::from_millis(route.def.upstream_timeout_ms);

        // Rewrite the request for the upstream.
        let (mut parts, body) = req.into_parts();
        let path_and_query =
            rewrite::upstream_path_and_query(&route, parts.uri.path(), parts.uri.query());
        let upstream_uri = Uri::builder()
            .scheme(route.target_scheme.clone())
            .authority(route.target_authority.clone())
            .path_and_query(path_and_query)
            .build();
        let upstream_uri = match upstream_uri {
            Ok(uri) => uri,
            Err(err) => {
                tracing::error!(%api_id, error = %err, "failed to build upstream URI");
                return error_response(StatusCode::BAD_GATEWAY, "invalid upstream request");
            }
        };
        parts.uri = upstream_uri;
        // The upstream connection is negotiated by the client independently
        // of the client-facing protocol version.
        parts.version = Version::HTTP_11;
        rewrite::prepare_upstream_headers(&mut parts.headers, &route, remote_addr.ip());
        let upstream_req = Request::from_parts(parts, body);

        tracing::debug!(%api_id, uri = %upstream_req.uri(), "forwarding upstream");
        match tokio::time::timeout(timeout, self.client.request(upstream_req)).await {
            Ok(Ok(mut resp)) => {
                rewrite::strip_hop_by_hop_headers(resp.headers_mut());
                resp.map(|b| b.map_err(BoxError::from).boxed())
            }
            Ok(Err(err)) => {
                tracing::warn!(%api_id, error = %err, "upstream request failed");
                error_response(StatusCode::BAD_GATEWAY, "upstream request failed")
            }
            Err(_elapsed) => {
                tracing::warn!(%api_id, timeout_ms = timeout.as_millis(), "upstream timed out");
                error_response(StatusCode::GATEWAY_TIMEOUT, "upstream request timed out")
            }
        }
    }
}

/// Builds a JSON error response: `{"error": "<message>"}`.
fn error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body = serde_json::json!({ "error": message }).to_string();
    json_response(status, body)
}

/// Builds the `/hello` / `/ready` liveness body.
fn health_response() -> Response<ProxyBody> {
    let body = serde_json::json!({
        "status": "pass",
        "version": VERSION,
        "description": "g2way API gateway",
    })
    .to_string();
    json_response(StatusCode::OK, body)
}

fn json_response(status: StatusCode, body: String) -> Response<ProxyBody> {
    let mut resp = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|infallible| match infallible {})
            .boxed(),
    );
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::RouteTable;
    use g2_core::ApiDefinition;
    use http_body_util::Empty;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    type TestBody = Full<Bytes>;

    const CLIENT: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 55555);

    /// Spawns an echo upstream returning `"<METHOD> <path?query>"` in the
    /// body and the received `host` header in `x-echo-host`.
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
                        let host = req
                            .headers()
                            .get(header::HOST)
                            .cloned()
                            .unwrap_or(HeaderValue::from_static("<none>"));
                        let xff = req
                            .headers()
                            .get("x-forwarded-for")
                            .cloned()
                            .unwrap_or(HeaderValue::from_static("<none>"));
                        let body = format!("{} {}", req.method(), req.uri());
                        let mut resp = Response::new(Full::new(Bytes::from(body)));
                        resp.headers_mut().insert("x-echo-host", host);
                        resp.headers_mut().insert("x-echo-xff", xff);
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

    fn gateway_for(defs: Vec<ApiDefinition>) -> Gateway<TestBody> {
        Gateway::new(RouteTable::build(defs).expect("table"))
    }

    fn def_to(api_id: &str, listen_path: &str, target: &str) -> ApiDefinition {
        serde_json::from_str(&format!(
            r#"{{"api_id":"{api_id}","name":"{api_id}","listen_path":"{listen_path}","target_url":"{target}"}}"#
        ))
        .expect("def")
    }

    fn get(uri: &str) -> Request<TestBody> {
        Request::builder()
            .uri(uri)
            .header(header::HOST, "gw.example.com")
            .body(Full::new(Bytes::new()))
            .expect("request")
    }

    async fn body_string(resp: Response<ProxyBody>) -> String {
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    #[tokio::test]
    async fn proxies_to_upstream_with_stripped_path() {
        let upstream = spawn_echo_upstream().await;
        let gw = gateway_for(vec![def_to(
            "echo",
            "/echo/",
            &format!("http://{upstream}"),
        )]);

        let resp = gw.handle(get("/echo/foo/bar?x=1"), CLIENT).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let host = resp.headers().get("x-echo-host").cloned().expect("host");
        let xff = resp.headers().get("x-echo-xff").cloned().expect("xff");
        assert_eq!(body_string(resp).await, "GET /foo/bar?x=1");
        // Host was rewritten to the upstream authority by default…
        assert_eq!(host.to_str().expect("host str"), upstream.to_string());
        // …and the client IP was recorded.
        assert_eq!(xff.to_str().expect("xff str"), "127.0.0.1");
    }

    #[tokio::test]
    async fn preserves_host_when_configured() {
        let upstream = spawn_echo_upstream().await;
        let mut def = def_to("echo", "/echo/", &format!("http://{upstream}"));
        def.preserve_host_header = true;
        let gw = gateway_for(vec![def]);

        let resp = gw.handle(get("/echo/x"), CLIENT).await;
        assert_eq!(
            resp.headers().get("x-echo-host").expect("host").as_bytes(),
            b"gw.example.com"
        );
    }

    #[tokio::test]
    async fn unmatched_path_is_404_json() {
        let gw = gateway_for(vec![]);
        let resp = gw.handle(get("/nope"), CLIENT).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .expect("ct")
                .as_bytes(),
            b"application/json"
        );
        assert!(body_string(resp).await.contains("no API found"));
    }

    #[tokio::test]
    async fn unreachable_upstream_is_502() {
        // Bind-then-drop a listener to obtain a port with nothing behind it.
        let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = dead.local_addr().expect("addr");
        drop(dead);

        let gw = gateway_for(vec![def_to("down", "/down/", &format!("http://{addr}"))]);
        let resp = gw.handle(get("/down/x"), CLIENT).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn slow_upstream_is_504() {
        // An upstream that accepts connections but never responds.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                // Hold the socket open without answering.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    drop(stream);
                });
            }
        });

        let mut def = def_to("slow", "/slow/", &format!("http://{addr}"));
        def.upstream_timeout_ms = 100;
        let gw = gateway_for(vec![def]);
        let resp = gw.handle(get("/slow/x"), CLIENT).await;
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn health_endpoints_bypass_routing() {
        // Even a catch-all API on `/` must not shadow health endpoints.
        let upstream = spawn_echo_upstream().await;
        let gw = gateway_for(vec![def_to("all", "/", &format!("http://{upstream}"))]);

        for path in ["/hello", "/ready"] {
            let resp = gw.handle(get(path), CLIENT).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_string(resp).await;
            assert!(body.contains("\"status\":\"pass\""), "body: {body}");
        }
    }

    #[tokio::test]
    async fn reload_swaps_routes_atomically() {
        let upstream = spawn_echo_upstream().await;
        let gw = gateway_for(vec![]);
        assert_eq!(gw.route_count(), 0);
        assert_eq!(
            gw.handle(get("/echo/x"), CLIENT).await.status(),
            StatusCode::NOT_FOUND
        );

        let table = RouteTable::build(vec![def_to(
            "echo",
            "/echo/",
            &format!("http://{upstream}"),
        )])
        .expect("table");
        gw.reload(table);
        assert_eq!(gw.route_count(), 1);
        assert_eq!(
            gw.handle(get("/echo/x"), CLIENT).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn hop_by_hop_headers_are_stripped_from_upstream_response() {
        // Upstream that answers with a hop-by-hop header.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let service = service_fn(|_req: Request<Incoming>| async move {
                        let mut resp = Response::new(Empty::<Bytes>::new());
                        resp.headers_mut()
                            .insert("keep-alive", HeaderValue::from_static("timeout=5"));
                        resp.headers_mut()
                            .insert("x-app", HeaderValue::from_static("kept"));
                        Ok::<_, std::convert::Infallible>(resp)
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        let gw = gateway_for(vec![def_to("h", "/h/", &format!("http://{addr}"))]);
        let resp = gw.handle(get("/h/x"), CLIENT).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("keep-alive").is_none());
        assert_eq!(
            resp.headers().get("x-app").expect("kept").as_bytes(),
            b"kept"
        );
    }
}
