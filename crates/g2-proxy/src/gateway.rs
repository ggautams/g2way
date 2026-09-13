//! The [`Gateway`]: per-request entry point tying routing and each route's
//! prebuilt middleware chain together.

use std::net::SocketAddr;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hyper::body::Body;
use tower::ServiceExt;

use crate::response::{error_response, health_response};
use crate::router::RouteTable;

pub use g2_middleware::{BoxError, ProxyBody};

/// The proxy engine shared by all connections of a gateway process.
///
/// The route table lives in an [`ArcSwap`]: requests load it wait-free, and
/// [`Gateway::reload`] swaps in a new table atomically. Each route carries a
/// fully composed middleware chain (ending in the upstream forwarder) built
/// at table-build time; per request the gateway only clones that boxed chain
/// and drives it — no locks, no composition on the hot path.
pub struct Gateway {
    table: ArcSwap<RouteTable>,
}

impl Gateway {
    /// Creates a gateway serving `table`.
    #[must_use]
    pub fn new(table: RouteTable) -> Self {
        Self {
            table: ArcSwap::from_pointee(table),
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

    /// Handles to the currently served routes, most specific first (for the
    /// dashboard-support API). The snapshot stays valid across reloads —
    /// it simply describes the table that was live when it was taken.
    #[must_use]
    pub fn routes_snapshot(&self) -> Vec<std::sync::Arc<crate::router::Route>> {
        self.table.load().routes().to_vec()
    }

    /// Handles one client request end to end.
    ///
    /// Generic over the request body `B` so production code passes hyper's
    /// streaming `Incoming` while tests inject synthetic bodies; the body is
    /// boxed into [`ProxyBody`] at the chain boundary.
    ///
    /// Never returns an error: every failure is mapped to an HTTP error
    /// response (`404` no matching API; `502`/`504` and later `401`/`429`
    /// come from inside the chain).
    pub async fn handle<B>(&self, req: Request<B>, remote_addr: SocketAddr) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Send + Sync + 'static,
        B::Error: Into<BoxError>,
    {
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
        let chain = route.chain.clone();
        drop(table);

        let mut req = req.map(ProxyBody::new);
        req.extensions_mut()
            .insert(g2_middleware::ClientAddr(remote_addr));
        match chain.oneshot(req).await {
            Ok(resp) => resp,
            Err(never) => match never {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::Forwarder;
    use crate::router::RouteTable;
    use g2_core::ApiDefinition;
    use g2_middleware::API_ID_HEADER;
    use http::{header, HeaderValue};
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::net::TcpListener;

    type TestBody = Full<Bytes>;

    const CLIENT: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 55555);

    /// Spawns an echo upstream returning `"<METHOD> <path?query>"` in the
    /// body and the received `host` / `x-forwarded-for` / `x-g2-api-id`
    /// headers in `x-echo-*` response headers.
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
                        let api_id = req
                            .headers()
                            .get(API_ID_HEADER)
                            .cloned()
                            .unwrap_or(HeaderValue::from_static("<none>"));
                        let body = format!("{} {}", req.method(), req.uri());
                        let mut resp = Response::new(Full::new(Bytes::from(body)));
                        resp.headers_mut().insert("x-echo-host", host);
                        resp.headers_mut().insert("x-echo-xff", xff);
                        resp.headers_mut().insert("x-echo-api-id", api_id);
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

    fn memory_storage() -> g2_storage::SharedStorage {
        std::sync::Arc::new(g2_storage::MemoryStorage::new())
    }

    fn gateway_with_storage(
        defs: Vec<ApiDefinition>,
        storage: &g2_storage::SharedStorage,
    ) -> Gateway {
        Gateway::new(
            RouteTable::build(defs, &Forwarder::new(), storage, None, None, None).expect("table"),
        )
    }

    fn gateway_for(defs: Vec<ApiDefinition>) -> Gateway {
        gateway_with_storage(defs, &memory_storage())
    }

    /// A keyless definition (most tests exercise routing/forwarding, not auth).
    fn def_to(api_id: &str, listen_path: &str, target: &str) -> ApiDefinition {
        serde_json::from_str(&format!(
            r#"{{"api_id":"{api_id}","name":"{api_id}","listen_path":"{listen_path}","target_url":"{target}","auth":{{"mode":"keyless"}}}}"#
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
    async fn chain_stamps_api_id_header_upstream() {
        let upstream = spawn_echo_upstream().await;
        let gw = gateway_for(vec![def_to(
            "echo",
            "/echo/",
            &format!("http://{upstream}"),
        )]);

        // A client-supplied value must be overwritten by the chain.
        let mut req = get("/echo/x");
        req.headers_mut()
            .insert(API_ID_HEADER, HeaderValue::from_static("spoofed"));
        let resp = gw.handle(req, CLIENT).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-echo-api-id")
                .expect("api id")
                .as_bytes(),
            b"echo"
        );
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

        let table = RouteTable::build(
            vec![def_to("echo", "/echo/", &format!("http://{upstream}"))],
            &Forwarder::new(),
            &memory_storage(),
            None,
            None,
            None,
        )
        .expect("table");
        gw.reload(table);
        assert_eq!(gw.route_count(), 1);
        assert_eq!(
            gw.handle(get("/echo/x"), CLIENT).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn token_protected_api_end_to_end() {
        use g2_core::session::{hash_key, session_storage_key};
        use g2_core::KeySession;

        let upstream = spawn_echo_upstream().await;
        let storage = memory_storage();
        storage
            .set(
                &session_storage_key("default", &hash_key("s3cret")),
                &serde_json::to_string(&KeySession::default()).expect("json"),
                None,
            )
            .await
            .expect("seed session");

        // No "auth" field: token auth on the Authorization header by default.
        let def: ApiDefinition = serde_json::from_str(&format!(
            r#"{{"api_id":"sec","name":"sec","listen_path":"/sec/","target_url":"http://{upstream}"}}"#
        ))
        .expect("def");
        let gw = gateway_with_storage(vec![def], &storage);

        // Missing token → 401.
        let resp = gw.handle(get("/sec/x"), CLIENT).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong token → 403.
        let mut req = get("/sec/x");
        req.headers_mut()
            .insert("authorization", HeaderValue::from_static("wrong"));
        let resp = gw.handle(req, CLIENT).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Valid token → proxied upstream.
        let mut req = get("/sec/x");
        req.headers_mut()
            .insert("authorization", HeaderValue::from_static("Bearer s3cret"));
        let resp = gw.handle(req, CLIENT).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "GET /x");
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
