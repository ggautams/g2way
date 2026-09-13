//! End-to-end tests: a real g2way server proxying to a real upstream over TCP.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use g2_core::ApiDefinition;
use g2_proxy::{Forwarder, Gateway, RouteTable};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Spawns an HTTP/1.1 upstream echoing `"<METHOD> <path?query>"` plus the
/// request body length.
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
                    let api_id = req.headers().get("x-g2-api-id").cloned();
                    let head = format!("{} {}", req.method(), req.uri());
                    let body = req.collect().await.expect("body").to_bytes();
                    let reply = format!("{head} len={}", body.len());
                    let mut resp = Response::new(Full::new(Bytes::from(reply)));
                    if let Some(api_id) = api_id {
                        resp.headers_mut().insert("x-echo-api-id", api_id);
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

/// Starts a full g2way server for `defs` backed by `storage`; returns its
/// address and a shutdown trigger.
async fn spawn_gateway_with_storage(
    defs: Vec<ApiDefinition>,
    storage: g2_storage::SharedStorage,
) -> (SocketAddr, oneshot::Sender<()>) {
    let table = RouteTable::build(defs, &Forwarder::new(), &storage, None, None, None, None)
        .expect("route table");
    let gateway = Arc::new(Gateway::new(table));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        g2way::server::serve(
            listener,
            gateway,
            async {
                let _ = rx.await;
            },
            Duration::from_secs(5),
        )
        .await
        .expect("serve");
    });
    (addr, tx)
}

/// Starts a full g2way server for `defs`; returns its address and a shutdown
/// trigger.
async fn spawn_gateway(defs: Vec<ApiDefinition>) -> (SocketAddr, oneshot::Sender<()>) {
    spawn_gateway_with_storage(defs, Arc::new(g2_storage::MemoryStorage::new())).await
}

/// A keyless definition: these tests exercise proxying, not auth.
fn api(listen_path: &str, target: &str) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"e2e","name":"e2e","listen_path":"{listen_path}","target_url":"{target}","auth":{{"mode":"keyless"}}}}"#
    ))
    .expect("definition")
}

async fn http_get(url: &str) -> (StatusCode, String) {
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(url.parse().expect("url"))
        .await
        .expect("request");
    let status = resp.status();
    let body = resp.collect().await.expect("body").to_bytes();
    (status, String::from_utf8(body.to_vec()).expect("utf8"))
}

#[tokio::test]
async fn proxies_get_requests_end_to_end() {
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![api("/svc/", &format!("http://{upstream}"))]).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(
            format!("http://{gw}/svc/widgets?limit=5")
                .parse()
                .expect("url"),
        )
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::OK);
    // The middleware chain stamped the API id onto the upstream request.
    assert_eq!(
        resp.headers()
            .get("x-echo-api-id")
            .expect("api id header")
            .as_bytes(),
        b"e2e"
    );
    let body = resp.collect().await.expect("body").to_bytes();
    assert_eq!(&body[..], b"GET /widgets?limit=5 len=0");
}

#[tokio::test]
async fn proxies_post_bodies_end_to_end() {
    let upstream = spawn_echo_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![api("/svc/", &format!("http://{upstream}"))]).await;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::post(format!("http://{gw}/svc/items"))
        .body(Full::new(Bytes::from_static(b"hello-upstream")))
        .expect("request");
    let resp = client.request(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.collect().await.expect("body").to_bytes();
    assert_eq!(&body[..], b"POST /items len=14");
}

#[tokio::test]
async fn url_rewrite_and_method_transform_reach_the_upstream() {
    let upstream = spawn_echo_upstream().await;
    let mut def = api("/svc/", &format!("http://{upstream}"));
    def.url_rewrites = vec![g2_core::UrlRewriteRule {
        pattern: r"^/svc/widgets/(\d+)$".into(),
        rewrite: "/rewritten/$1".into(),
    }];
    def.transform_method = Some("POST".into());
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    // Matching request: rewritten path, transformed method, query kept.
    let (status, body) = http_get(&format!("http://{gw}/svc/widgets/42?limit=5")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "POST /rewritten/42?limit=5 len=0");

    // Non-matching path: normal listen-path strip, method still transformed.
    let (status, body) = http_get(&format!("http://{gw}/svc/other")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "POST /other len=0");
}

#[tokio::test]
async fn path_lists_and_mock_responses_end_to_end() {
    let upstream = spawn_echo_upstream().await;

    // A protected API (default token auth, empty key store) where one path
    // is ignored (public) and mocked, and one path is blocked outright.
    let mut def = serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"pl","name":"pl","listen_path":"/pl/","target_url":"http://{upstream}"}}"#
    ))
    .expect("definition");
    def.block_paths = vec![g2_core::PathRule {
        pattern: "^/pl/internal/".into(),
        methods: vec![],
    }];
    def.ignore_auth_paths = vec![g2_core::PathRule {
        pattern: "^/pl/status$".into(),
        methods: vec![],
    }];
    def.mock_responses = vec![g2_core::MockResponse {
        pattern: "^/pl/status$".into(),
        methods: vec!["GET".into()],
        status: 200,
        body: r#"{"status":"up"}"#.into(),
        headers: [("Content-Type".to_owned(), "application/json".to_owned())].into(),
    }];
    def.validate().expect("valid definition");
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    // Ignored + mocked path: answered by the gateway, no credentials needed.
    let (status, body) = http_get(&format!("http://{gw}/pl/status")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"status":"up"}"#);

    // Blocked path: 403 before auth (not 401).
    let (status, body) = http_get(&format!("http://{gw}/pl/internal/x")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("forbidden"), "body: {body}");

    // Every other path still requires credentials.
    let (status, _) = http_get(&format!("http://{gw}/pl/widgets")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn serves_health_and_404_end_to_end() {
    let (gw, _stop) = spawn_gateway(vec![]).await;

    let (status, body) = http_get(&format!("http://{gw}/hello")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"status\":\"pass\""), "body: {body}");

    let (status, body) = http_get(&format!("http://{gw}/unrouted")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("no API found"), "body: {body}");
}

#[tokio::test]
async fn token_auth_end_to_end() {
    use g2_core::session::{hash_key, session_storage_key};

    let upstream = spawn_echo_upstream().await;
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    storage
        .set(
            &session_storage_key("default", &hash_key("e2e-key")),
            &serde_json::to_string(&g2_core::KeySession::default()).expect("json"),
            None,
        )
        .await
        .expect("seed key");

    // Default auth mode: token on the Authorization header.
    let def = serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"sec","name":"sec","listen_path":"/sec/","target_url":"http://{upstream}"}}"#
    ))
    .expect("definition");
    let (gw, _stop) = spawn_gateway_with_storage(vec![def], storage).await;

    // No credential → 401 JSON error.
    let (status, body) = http_get(&format!("http://{gw}/sec/x")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("authorization field missing"), "body: {body}");

    // Valid bearer token → proxied.
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::get(format!("http://{gw}/sec/x"))
        .header("authorization", "Bearer e2e-key")
        .body(Empty::<Bytes>::new())
        .expect("request");
    let resp = client.request(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn rate_limit_end_to_end() {
    use g2_core::session::{hash_key, session_storage_key, RateLimit};

    let upstream = spawn_echo_upstream().await;
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let session = g2_core::KeySession {
        rate: Some(RateLimit {
            requests: 2,
            per_seconds: 60,
        }),
        ..g2_core::KeySession::default()
    };
    storage
        .set(
            &session_storage_key("default", &hash_key("limited-key")),
            &serde_json::to_string(&session).expect("json"),
            None,
        )
        .await
        .expect("seed key");

    let def = serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"rl","name":"rl","listen_path":"/rl/","target_url":"http://{upstream}"}}"#
    ))
    .expect("definition");
    let (gw, _stop) = spawn_gateway_with_storage(vec![def], storage).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let call = || async {
        let req = Request::get(format!("http://{gw}/rl/x"))
            .header("authorization", "Bearer limited-key")
            .body(Empty::<Bytes>::new())
            .expect("request");
        client.request(req).await.expect("response")
    };

    for _ in 0..2 {
        assert_eq!(call().await.status(), StatusCode::OK);
    }
    let resp = call().await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-limit")
            .expect("limit header")
            .as_bytes(),
        b"2"
    );
    assert!(resp.headers().contains_key("x-ratelimit-reset"));
    assert!(resp.headers().contains_key("retry-after"));
}

#[tokio::test]
async fn basic_auth_end_to_end() {
    use base64::Engine as _;
    use g2_core::session::{hash_key, session_storage_key};

    let upstream = spawn_echo_upstream().await;
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let session = g2_core::KeySession {
        basic_auth: Some(g2_core::BasicAuthData {
            // Minimum bcrypt cost keeps the test fast.
            password_hash: bcrypt::hash("hunter2", 4).expect("hash"),
        }),
        ..g2_core::KeySession::default()
    };
    storage
        .set(
            &session_storage_key("default", &hash_key("basic:alice")),
            &serde_json::to_string(&session).expect("json"),
            None,
        )
        .await
        .expect("seed user");

    let def = serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"ba","name":"ba","listen_path":"/ba/","target_url":"http://{upstream}","auth":{{"mode":"basic_auth"}}}}"#
    ))
    .expect("definition");
    let (gw, _stop) = spawn_gateway_with_storage(vec![def], storage).await;

    // No credential → 401 with the Basic challenge.
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(format!("http://{gw}/ba/x").parse().expect("url"))
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get("www-authenticate")
            .expect("challenge")
            .as_bytes(),
        b"Basic realm=\"g2way\""
    );

    // Valid credentials → proxied.
    let encoded = base64::engine::general_purpose::STANDARD.encode("alice:hunter2");
    let req = Request::get(format!("http://{gw}/ba/x"))
        .header("authorization", format!("Basic {encoded}"))
        .body(Empty::<Bytes>::new())
        .expect("request");
    let resp = client.request(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn shuts_down_on_signal_and_refuses_new_connections() {
    let (gw, stop) = spawn_gateway(vec![]).await;
    let (status, _) = http_get(&format!("http://{gw}/hello")).await;
    assert_eq!(status, StatusCode::OK);

    stop.send(()).expect("trigger shutdown");
    // Give the accept loop a moment to wind down, then verify the port no
    // longer accepts fresh connections.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let refused = tokio::net::TcpStream::connect(gw).await;
    assert!(refused.is_err(), "gateway still accepting after shutdown");
}
