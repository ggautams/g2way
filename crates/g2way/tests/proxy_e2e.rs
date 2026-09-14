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
async fn response_caching_end_to_end() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // An upstream that answers with how many requests it has served, so a
    // replayed (cached) response is distinguishable from a fresh one.
    let counter = Arc::new(AtomicUsize::new(0));
    let upstream_counter = Arc::clone(&counter);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let upstream = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let counter = Arc::clone(&upstream_counter);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    async move {
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            format!("count={n}"),
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let mut def = api("/c/", &format!("http://{upstream}"));
    def.cache = Some(serde_json::from_str("{}").expect("cache defaults"));
    def.validate().expect("valid definition");
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let (gw, _stop) = spawn_gateway_with_storage(vec![def], Arc::clone(&storage)).await;

    // First request misses and reaches the upstream.
    let (status, body) = http_get(&format!("http://{gw}/c/data?q=1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "count=1");

    // The entry is written in the background after the body completes.
    let mut written = false;
    for _ in 0..100 {
        if !g2_storage::Storage::scan_prefix(storage.as_ref(), "g2:default:cache:")
            .await
            .expect("scan")
            .is_empty()
        {
            written = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(written, "cache entry never written");

    // The repeat request is served from cache: same body, marked as a hit,
    // and the upstream is not contacted again.
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .get(format!("http://{gw}/c/data?q=1").parse().expect("url"))
        .await
        .expect("request");
    assert_eq!(
        resp.headers()
            .get("x-g2-cache")
            .expect("hit marker")
            .as_bytes(),
        b"hit"
    );
    let body = resp.collect().await.expect("body").to_bytes();
    assert_eq!(&body[..], b"count=1");
    assert_eq!(counter.load(Ordering::SeqCst), 1, "upstream hit again");

    // A different query is a different entry; an unsafe method bypasses the
    // cache entirely.
    let (_, body) = http_get(&format!("http://{gw}/c/data?q=2")).await;
    assert_eq!(body, "count=2");
    let post_client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::post(format!("http://{gw}/c/data?q=1"))
        .body(Empty::new())
        .expect("request");
    let resp = post_client.request(req).await.expect("response");
    let body = resp.collect().await.expect("body").to_bytes();
    assert_eq!(&body[..], b"count=3", "POST must not be served from cache");
}

#[tokio::test]
async fn api_versioning_end_to_end() {
    let upstream = spawn_echo_upstream().await;

    // v1 (the default) proxies as-is; v2 overrides the upstream path via a
    // rewrite; "retired" is expired and must be refused.
    let mut def = api("/v/", &format!("http://{upstream}"));
    def.versioning = Some(
        serde_json::from_str(
            r#"{
                "default_version": "v1",
                "versions": {
                    "v1": {},
                    "v2": {"url_rewrites": [{"pattern": "^/v/(.*)$", "rewrite": "/two/$1"}]},
                    "retired": {"expires_at": 1}
                }
            }"#,
        )
        .expect("versioning JSON"),
    );
    def.validate().expect("valid definition");
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    let get_version = |version: Option<&'static str>| async move {
        let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let mut req = Request::get(format!("http://{gw}/v/widgets"));
        if let Some(version) = version {
            req = req.header("x-api-version", version);
        }
        let resp = client
            .request(req.body(Empty::new()).expect("request"))
            .await
            .expect("response");
        let status = resp.status();
        let body = resp.collect().await.expect("body").to_bytes();
        (status, String::from_utf8(body.to_vec()).expect("utf8"))
    };

    // No version named: the default (v1) serves, plain listen-path strip.
    let (status, body) = get_version(None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "GET /widgets len=0");

    // v2: its overriding rewrite decides the upstream path.
    let (status, body) = get_version(Some("v2")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "GET /two/widgets len=0");

    // Expired and unknown versions are refused.
    let (status, body) = get_version(Some("retired")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("expired"), "body: {body}");
    let (status, body) = get_version(Some("v9")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("does not exist"), "body: {body}");
}

#[tokio::test]
async fn cors_end_to_end() {
    let upstream = spawn_echo_upstream().await;
    let mut def = api("/cors/", &format!("http://{upstream}"));
    def.cors = Some(
        serde_json::from_str(
            r#"{"allowed_origins": ["https://app.example.com"],
                "allowed_methods": ["GET", "DELETE"],
                "max_age_secs": 300}"#,
        )
        .expect("cors config"),
    );
    def.validate().expect("valid definition");
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    // Preflight: answered by the gateway itself, upstream never contacted.
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::options(format!("http://{gw}/cors/items"))
        .header("origin", "https://app.example.com")
        .header("access-control-request-method", "DELETE")
        .body(Empty::new())
        .expect("request");
    let resp = client.request(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(resp.headers().get("x-echo-api-id").is_none());
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .expect("allow-origin")
            .as_bytes(),
        b"https://app.example.com"
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-methods")
            .expect("allow-methods")
            .as_bytes(),
        b"GET, DELETE"
    );
    assert_eq!(
        resp.headers()
            .get("access-control-max-age")
            .expect("max-age")
            .as_bytes(),
        b"300"
    );

    // Actual cross-origin request: proxied and decorated.
    let req = Request::get(format!("http://{gw}/cors/items"))
        .header("origin", "https://app.example.com")
        .body(Empty::new())
        .expect("request");
    let resp = client.request(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-echo-api-id").is_some());
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .expect("allow-origin")
            .as_bytes(),
        b"https://app.example.com"
    );
}

#[tokio::test]
async fn ip_block_list_rejects_the_client_end_to_end() {
    let upstream = spawn_echo_upstream().await;
    // The test client connects from 127.0.0.1, so blocking the loopback
    // network must reject it before anything else runs.
    let mut blocked = api("/blocked/", &format!("http://{upstream}"));
    blocked.block_ips = vec!["127.0.0.0/8".into()];
    let mut open = api("/open/", &format!("http://{upstream}"));
    open.api_id = "e2e-open".into();
    open.allow_ips = vec!["127.0.0.1".into()];
    for def in [&blocked, &open] {
        def.validate().expect("valid definition");
    }
    let (gw, _stop) = spawn_gateway(vec![blocked, open]).await;

    let (status, body) = http_get(&format!("http://{gw}/blocked/x")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("forbidden"), "body: {body}");

    // An allow list matching the client keeps the API reachable.
    let (status, _) = http_get(&format!("http://{gw}/open/x")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn request_size_limit_end_to_end() {
    let upstream = spawn_echo_upstream().await;
    let mut def = api("/sized/", &format!("http://{upstream}"));
    def.max_request_body_bytes = Some(10);
    def.validate().expect("valid definition");
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    // Declared Content-Length over the limit: rejected up front.
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::post(format!("http://{gw}/sized/upload"))
        .body(Full::new(Bytes::from(vec![b'x'; 11])))
        .expect("request");
    let resp = client.request(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Within the limit: proxied normally.
    let req = Request::post(format!("http://{gw}/sized/upload"))
        .body(Full::new(Bytes::from(vec![b'x'; 10])))
        .expect("request");
    let resp = client.request(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.collect().await.expect("body").to_bytes();
    assert_eq!(&body[..], b"POST /upload len=10");

    // A chunked body with no declared length is caught mid-stream (the
    // forwarder maps the aborted upstream send to 413, not 502).
    use http_body_util::StreamBody;
    let frames = futures_util::stream::iter(
        std::iter::repeat_with(|| {
            Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(Bytes::from_static(
                b"12345678",
            )))
        })
        .take(4),
    );
    let client: Client<_, StreamBody<_>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::post(format!("http://{gw}/sized/upload"))
        .body(StreamBody::new(frames))
        .expect("request");
    let resp = client.request(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn upstream_retries_and_circuit_breaker_end_to_end() {
    let live = spawn_echo_upstream().await;
    // Bind-then-drop a listener to obtain a port with nothing behind it.
    let dead_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let dead = dead_listener.local_addr().expect("addr");
    drop(dead_listener);

    let mut lb = api("/lb/", "http://unused.internal");
    lb.target_list = vec![format!("http://{dead}"), format!("http://{live}")];
    lb.upstream_retries = 1;
    let mut cb = api("/cb/", &format!("http://{dead}"));
    cb.api_id = "cb".into();
    cb.circuit_breaker = Some(serde_json::from_str(r#"{"failure_threshold": 2}"#).expect("cfg"));
    let (gw, _stop) = spawn_gateway(vec![lb, cb]).await;

    // A real client GET has an empty (end-of-stream) body all the way
    // through the chain, so a dead load-balancing pick is retried against
    // the live address: every request succeeds.
    for _ in 0..4 {
        let (status, body) = http_get(&format!("http://{gw}/lb/ping")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "GET /ping len=0");
    }

    // Two consecutive 502s trip the breaker; the third request is shed
    // with 503 without contacting the upstream.
    for _ in 0..2 {
        let (status, _) = http_get(&format!("http://{gw}/cb/ping")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }
    let (status, body) = http_get(&format!("http://{gw}/cb/ping")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("circuit open"), "got: {body}");
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

#[tokio::test]
async fn jwt_jwks_end_to_end() {
    use std::sync::Mutex;

    // Same throwaway keypair as g2-middleware's JWT unit tests.
    const TEST_RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9vQS0xUUdaCmm
2MuakxbnoUGSCzeKns0F3C3x7I/CSuPV1ckdPIGfOoveNs+mSHI6Z5MwR4SvJcxu
wJZz8dmd9UXHLhr/R2MpOA5cLMdS7ZyVfKrUC0blvWuJ9Un8M2ONmtx97L6c9k07
1HD9MX9NVJlsKKOhF7hvuL+C5Wc8dUsE8TjnHkZ4pCQcHB5eY1BEzHXA0uZqTgsy
4+YfqQ9cT4O+XPVlnPPGuyNe94F/NGqDH0ogfQjc9AEqPVsrOoyejY/oBHmwhSrf
7d8lDzTN6M2KR9L6mZUKUafCKdxw9cfyI/RQRpQq0SK6aeN4/LOiCpvliI+U6Lfd
2MsWr7T/AgMBAAECggEAB5UVKhA0Gd++wl8pi8zS/oCwOSDfoFeGQ/SvlVppyE7r
2fDIL7XqTC2vxzqTg8ajYfgfpq9E+ybci5SArrN8idZyampKQ+dbbBtEX6Sedo7u
Uf8AaKbmt2mhcYru4PhAwzjsFNAwMd+Z6Ikt1sByoOl/lBXvrBFhmn1ckeOPA5hu
j6n2AZyG/nePtFU0y9gi1FTDECM8B2dliQyCzU7LvjpCCbRD0EiKYP7ZpUzIHC65
9WR6RRC3onLe28CueTD3QvAvYsP4QeeiI5wDpvYmLQvowGovRbiAVOHDRqG08gtY
cZSpyVuKmyi6kkRL19wbsTxdyH+elP6Chg1SUowP2QKBgQD/V/SCRSeGV8RrC2AR
rTtujEu73sTOY4kMaDz6LqVk9O3SbqL0ZG1fHP+bah+rA/4LjHbPozbH8d1DXrNc
cVOHoYnVsWp4NWvv7n5OnVUVxr7arbvsX+dDPlcdMQTRyaAV0zL0SmHQN3jqPzb4
BuEqlH6eCzYCngHRi7la3G0X5QKBgQC+OeM7zmL+yPHjG2XS6yBjF6adDrJK/PQE
g+DmfD7lPtEAMnh2cXZ7ADdpcdHu0uha2LRvyCZq1e0SMBFzWd8ny7TQTxn0ZR24
6mIMxO+sWfKLtN4J/37/Qrt6mHo4hXxbIg8SAaiOgxkaLhbbAkobWM51NySaAKru
Fez21p5DEwKBgG1No1cYb0Ds1SHVbrxiYWyDFfBH/gszRHlRLbkSuq4qwpsvzQW8
76ylZy2KEiBMxzT+XeWoQkz41fR+11ydDlqi5bPaDG+Evr2oY90XMFLwDsbhU+5t
Zzu7teLDFwMOwj5VeBxmstREyrfLc6Zcm4p0onbY6bfZF4Ixw5iHfxOZAoGAEwGN
pqgUVAiXwm02W0CK19vBFegmAEAN0XWrvtujHRyNnUttpcfoYpm+75Yjt4zzEkCc
pp6E2B/PtAWBeNj95uf/hOCiYzzHH3arnUL//2RtS3AizzTr520vdixN6d/McP6S
KuZnhPWsSGVaez9bUCgrWKLN0WVHrsoaBv+iiGkCgYEA+y+XusCUErqu/bqzzEYj
Oih8/7hU7lA0CEIx65jqY15F5Q2QDXv/s6j0JKdcWtSkdqq6w/yEbp/AHE8uamLo
OXYCPHHq5blRvGxnz1qnmVPHyVEYVjdboJiavY1gbwtK+wCBPS85htaRuFxFb9LD
NO+F4qDaW22QCAuvcoMJMDE=
-----END PRIVATE KEY-----";
    const TEST_RSA_N: &str = "vb0EtMVFHWgpptjLmpMW56FBkgs3ip7NBdwt8eyPwkrj1dXJHTyBnzqL3jbPpkhyOmeTMEeEryXMbsCWc_HZnfVFxy4a_0djKTgOXCzHUu2clXyq1AtG5b1rifVJ_DNjjZrcfey-nPZNO9Rw_TF_TVSZbCijoRe4b7i_guVnPHVLBPE45x5GeKQkHBweXmNQRMx1wNLmak4LMuPmH6kPXE-Dvlz1ZZzzxrsjXveBfzRqgx9KIH0I3PQBKj1bKzqMno2P6AR5sIUq3-3fJQ80zejNikfS-pmVClGnwinccPXH8iP0UEaUKtEiumnjePyzogqb5YiPlOi33djLFq-0_w";

    fn jwks_json(kid: &str) -> String {
        format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{TEST_RSA_N}","e":"AQAB"}}]}}"#
        )
    }

    fn rs256_token(kid: &str) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.into());
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            + 3600;
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({"sub": "dana", "exp": exp}),
            &jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes())
                .expect("private key"),
        )
        .expect("encode")
    }

    // A JWKS endpoint whose served key set can be swapped mid-test.
    let payload = Arc::new(Mutex::new(jwks_json("k1")));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind jwks");
    let jwks_addr = listener.local_addr().expect("jwks addr");
    let served = Arc::clone(&payload);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let service = service_fn(move |_req| {
                    let body = served.lock().expect("payload").clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            body,
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let upstream = spawn_echo_upstream().await;
    // 1s refresh so the rotation below is picked up by the periodic fetch.
    let def = serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"jwks","name":"jwks","listen_path":"/jwks/",
            "target_url":"http://{upstream}",
            "auth":{{"mode":"jwt","signing_method":"rs256",
                     "jwks_url":"http://{jwks_addr}/jwks.json",
                     "jwks_refresh_secs":1}}}}"#
    ))
    .expect("definition");
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let get_with_token = |token: String| {
        let client = client.clone();
        let url = format!("http://{gw}/jwks/x");
        async move {
            let req = Request::get(url)
                .header("authorization", format!("Bearer {token}"))
                .body(Empty::<Bytes>::new())
                .expect("request");
            client.request(req).await.expect("response").status()
        }
    };

    // No token → 401.
    let (status, _) = http_get(&format!("http://{gw}/jwks/x")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Token signed with the key the JWKS serves → proxied.
    assert_eq!(get_with_token(rs256_token("k1")).await, StatusCode::OK);

    // Garbage kid → the shared no-oracle 403.
    assert_eq!(
        get_with_token(rs256_token("ghost")).await,
        StatusCode::FORBIDDEN
    );

    // Key rotation: the endpoint now serves k2; the 1s periodic refresh
    // picks it up (the on-miss path alone is cooldown-limited).
    *payload.lock().expect("payload") = jwks_json("k2");
    let token = rs256_token("k2");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if get_with_token(token.clone()).await == StatusCode::OK {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("rotated key is picked up by the periodic refresh");
}

/// OIDC end to end: a fake IdP serves the discovery document and the JWKS;
/// the gateway validates iss/aud, maps the client id to a stored policy,
/// and proxies only compliant tokens.
#[tokio::test]
async fn oidc_end_to_end() {
    use g2_core::policy::policy_storage_key;
    use g2_core::Policy;

    // Same throwaway keypair as `jwt_jwks_end_to_end`.
    const TEST_RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9vQS0xUUdaCmm
2MuakxbnoUGSCzeKns0F3C3x7I/CSuPV1ckdPIGfOoveNs+mSHI6Z5MwR4SvJcxu
wJZz8dmd9UXHLhr/R2MpOA5cLMdS7ZyVfKrUC0blvWuJ9Un8M2ONmtx97L6c9k07
1HD9MX9NVJlsKKOhF7hvuL+C5Wc8dUsE8TjnHkZ4pCQcHB5eY1BEzHXA0uZqTgsy
4+YfqQ9cT4O+XPVlnPPGuyNe94F/NGqDH0ogfQjc9AEqPVsrOoyejY/oBHmwhSrf
7d8lDzTN6M2KR9L6mZUKUafCKdxw9cfyI/RQRpQq0SK6aeN4/LOiCpvliI+U6Lfd
2MsWr7T/AgMBAAECggEAB5UVKhA0Gd++wl8pi8zS/oCwOSDfoFeGQ/SvlVppyE7r
2fDIL7XqTC2vxzqTg8ajYfgfpq9E+ybci5SArrN8idZyampKQ+dbbBtEX6Sedo7u
Uf8AaKbmt2mhcYru4PhAwzjsFNAwMd+Z6Ikt1sByoOl/lBXvrBFhmn1ckeOPA5hu
j6n2AZyG/nePtFU0y9gi1FTDECM8B2dliQyCzU7LvjpCCbRD0EiKYP7ZpUzIHC65
9WR6RRC3onLe28CueTD3QvAvYsP4QeeiI5wDpvYmLQvowGovRbiAVOHDRqG08gtY
cZSpyVuKmyi6kkRL19wbsTxdyH+elP6Chg1SUowP2QKBgQD/V/SCRSeGV8RrC2AR
rTtujEu73sTOY4kMaDz6LqVk9O3SbqL0ZG1fHP+bah+rA/4LjHbPozbH8d1DXrNc
cVOHoYnVsWp4NWvv7n5OnVUVxr7arbvsX+dDPlcdMQTRyaAV0zL0SmHQN3jqPzb4
BuEqlH6eCzYCngHRi7la3G0X5QKBgQC+OeM7zmL+yPHjG2XS6yBjF6adDrJK/PQE
g+DmfD7lPtEAMnh2cXZ7ADdpcdHu0uha2LRvyCZq1e0SMBFzWd8ny7TQTxn0ZR24
6mIMxO+sWfKLtN4J/37/Qrt6mHo4hXxbIg8SAaiOgxkaLhbbAkobWM51NySaAKru
Fez21p5DEwKBgG1No1cYb0Ds1SHVbrxiYWyDFfBH/gszRHlRLbkSuq4qwpsvzQW8
76ylZy2KEiBMxzT+XeWoQkz41fR+11ydDlqi5bPaDG+Evr2oY90XMFLwDsbhU+5t
Zzu7teLDFwMOwj5VeBxmstREyrfLc6Zcm4p0onbY6bfZF4Ixw5iHfxOZAoGAEwGN
pqgUVAiXwm02W0CK19vBFegmAEAN0XWrvtujHRyNnUttpcfoYpm+75Yjt4zzEkCc
pp6E2B/PtAWBeNj95uf/hOCiYzzHH3arnUL//2RtS3AizzTr520vdixN6d/McP6S
KuZnhPWsSGVaez9bUCgrWKLN0WVHrsoaBv+iiGkCgYEA+y+XusCUErqu/bqzzEYj
Oih8/7hU7lA0CEIx65jqY15F5Q2QDXv/s6j0JKdcWtSkdqq6w/yEbp/AHE8uamLo
OXYCPHHq5blRvGxnz1qnmVPHyVEYVjdboJiavY1gbwtK+wCBPS85htaRuFxFb9LD
NO+F4qDaW22QCAuvcoMJMDE=
-----END PRIVATE KEY-----";
    const TEST_RSA_N: &str = "vb0EtMVFHWgpptjLmpMW56FBkgs3ip7NBdwt8eyPwkrj1dXJHTyBnzqL3jbPpkhyOmeTMEeEryXMbsCWc_HZnfVFxy4a_0djKTgOXCzHUu2clXyq1AtG5b1rifVJ_DNjjZrcfey-nPZNO9Rw_TF_TVSZbCijoRe4b7i_guVnPHVLBPE45x5GeKQkHBweXmNQRMx1wNLmak4LMuPmH6kPXE-Dvlz1ZZzzxrsjXveBfzRqgx9KIH0I3PQBKj1bKzqMno2P6AR5sIUq3-3fJQ80zejNikfS-pmVClGnwinccPXH8iP0UEaUKtEiumnjePyzogqb5YiPlOi33djLFq-0_w";
    const AUDIENCE: &str = "g2way-e2e";

    // The fake IdP: one server answering both the discovery document and
    // the JWKS, dispatched by path. Its own address is the issuer.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind idp");
    let idp_addr = listener.local_addr().expect("idp addr");
    let issuer = format!("http://{idp_addr}");
    let jwks = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"k1","alg":"RS256","use":"sig","n":"{TEST_RSA_N}","e":"AQAB"}}]}}"#
    );
    let discovery = format!(r#"{{"issuer":"{issuer}","jwks_uri":"{issuer}/keys"}}"#);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (jwks, discovery) = (jwks.clone(), discovery.clone());
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let body = match req.uri().path() {
                        "/.well-known/openid-configuration" => discovery.clone(),
                        "/keys" => jwks.clone(),
                        other => panic!("fake IdP got unexpected path {other}"),
                    };
                    async move {
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            body,
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let token = |claims: &serde_json::Value| {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("k1".into());
        jsonwebtoken::encode(
            &header,
            claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes())
                .expect("private key"),
        )
        .expect("encode")
    };
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        + 3600;

    // Storage carries the policy the mapped client id resolves to.
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let policy = Policy {
        policy_id: "gold".into(),
        name: "gold".into(),
        org_id: "default".into(),
        active: true,
        rate: None,
        quota: None,
        access: [("oidc".to_owned(), Default::default())].into(),
    };
    storage
        .set(
            &policy_storage_key("default", "gold"),
            &serde_json::to_string(&policy).expect("json"),
            None,
        )
        .await
        .expect("seed policy");

    let upstream = spawn_echo_upstream().await;
    let def = serde_json::from_str::<ApiDefinition>(&format!(
        r#"{{"api_id":"oidc","name":"oidc","listen_path":"/oidc/",
            "target_url":"http://{upstream}",
            "auth":{{"mode":"oidc","issuer_url":"{issuer}",
                     "audiences":["{AUDIENCE}"],
                     "policy_map":{{"client-gold":"gold"}}}}}}"#
    ))
    .expect("definition");
    let (gw, _stop) = spawn_gateway_with_storage(vec![def], storage).await;

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let get_with_token = |token: String| {
        let client = client.clone();
        let url = format!("http://{gw}/oidc/x");
        async move {
            let req = Request::get(url)
                .header("authorization", format!("Bearer {token}"))
                .body(Empty::<Bytes>::new())
                .expect("request");
            client.request(req).await.expect("response").status()
        }
    };

    // No token → 401.
    let (status, _) = http_get(&format!("http://{gw}/oidc/x")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A compliant token whose client id maps to the seeded policy → 200.
    // Polled: right after boot the eager background fetch (discovery +
    // keys) may not have landed yet, and the on-miss refetch is
    // cooldown-gated behind it — requests inside that window 403.
    let good = token(&serde_json::json!({
        "sub": "dana", "iss": issuer, "aud": AUDIENCE,
        "azp": "client-gold", "exp": exp,
    }));
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if get_with_token(good.clone()).await == StatusCode::OK {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("discovered keys verify a compliant token");

    // Wrong audience → the shared no-oracle 403.
    let wrong_aud = serde_json::json!({
        "sub": "dana", "iss": issuer, "aud": "someone-else",
        "azp": "client-gold", "exp": exp,
    });
    assert_eq!(
        get_with_token(token(&wrong_aud)).await,
        StatusCode::FORBIDDEN
    );

    // Unmapped client id → 403.
    let unmapped = serde_json::json!({
        "sub": "dana", "iss": issuer, "aud": AUDIENCE,
        "azp": "client-unknown", "exp": exp,
    });
    assert_eq!(
        get_with_token(token(&unmapped)).await,
        StatusCode::FORBIDDEN
    );
}
