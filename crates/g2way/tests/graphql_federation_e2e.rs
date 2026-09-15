//! End-to-end federation tests: a real g2way server composing two real
//! GraphQL subgraph upstreams over TCP and executing federated queries
//! via `_entities` (milestone M9, ADR-0011), plus subgraph-mode
//! passthrough of a federating router's reserved queries.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use g2_core::ApiDefinition;
use g2_proxy::{Forwarder, Gateway, RouteResources, RouteTable};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const USERS_SDL: &str = r#"
    type Query { user(id: ID!): User }
    type User @key(fields: "id") { id: ID! name: String }
"#;

const REVIEWS_SDL: &str = r#"
    type Query { topReviews: [Review!]! }
    type Review { body: String }
    type User @key(fields: "id") { id: ID! @external reviews: [Review!] }
"#;

type SeenLog = Arc<Mutex<Vec<String>>>;

/// Spawns a fake GraphQL upstream answering by request-body content:
/// `reply(body)` produces the JSON response. Every body is recorded.
async fn spawn_subgraph(reply: fn(&str) -> String) -> (SocketAddr, SeenLog) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    let log: SeenLog = Arc::new(Mutex::new(Vec::new()));
    let task_log = Arc::clone(&log);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let log = Arc::clone(&task_log);
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let log = Arc::clone(&log);
                    async move {
                        let body =
                            String::from_utf8_lossy(&req.collect().await.expect("body").to_bytes())
                                .into_owned();
                        let response = reply(&body);
                        log.lock().expect("not poisoned").push(body);
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            response,
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, log)
}

fn users_reply(body: &str) -> String {
    if body.contains("_service") {
        return r#"{"data":{"_service":{"sdl":"type Query { user(id: ID!): User }"}}}"#.into();
    }
    if body.contains("_entities") {
        return r#"{"data":{"_entities":[{"__typename":"User","name":"Ada"}]}}"#.into();
    }
    r#"{"data":{"user":{"__typename":"User","name":"Ada","g2__id":"7"}}}"#.into()
}

fn reviews_reply(body: &str) -> String {
    if body.contains("_entities") {
        return r#"{"data":{"_entities":[
            {"__typename":"User","reviews":[{"__typename":"Review","body":"solid"}]}
        ]}}"#
            .into();
    }
    r#"{"data":{"topReviews":[]}}"#.into()
}

/// Starts a full g2way server for `defs`; returns its address and a
/// shutdown trigger.
async fn spawn_gateway(defs: Vec<ApiDefinition>) -> (SocketAddr, oneshot::Sender<()>) {
    let storage: g2_storage::SharedStorage = Arc::new(g2_storage::MemoryStorage::new());
    let table = RouteTable::build(defs, &RouteResources::new(&Forwarder::new(), &storage))
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

/// A keyless supergraph API over the two subgraph upstreams.
fn supergraph_api(users: SocketAddr, reviews: SocketAddr) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(
        &serde_json::json!({
            "api_id": "fed-e2e",
            "name": "fed-e2e",
            "listen_path": "/fed/",
            "target_url": "http://unused.invalid/",
            "auth": { "mode": "keyless" },
            "graphql": {
                "execution_mode": "supergraph",
                "supergraph": {
                    "subgraphs": [
                        { "name": "users",
                          "url": format!("http://{users}/graphql"),
                          "sdl": USERS_SDL },
                        { "name": "reviews",
                          "url": format!("http://{reviews}/graphql"),
                          "sdl": REVIEWS_SDL }
                    ]
                }
            }
        })
        .to_string(),
    )
    .expect("definition")
}

async fn post(gw: SocketAddr, path: &str, query: &str) -> (StatusCode, serde_json::Value) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{gw}{path}"))
        .body(Full::new(Bytes::from(
            serde_json::json!({ "query": query }).to_string(),
        )))
        .expect("request");
    let resp = client.request(req).await.expect("gateway reachable");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!(String::from_utf8_lossy(&bytes)));
    (status, json)
}

#[tokio::test]
async fn federated_query_stitches_across_real_subgraphs() {
    let (users, users_log) = spawn_subgraph(users_reply).await;
    let (reviews, reviews_log) = spawn_subgraph(reviews_reply).await;
    let (gw, _stop) = spawn_gateway(vec![supergraph_api(users, reviews)]).await;

    let (status, body) = post(gw, "/fed", r#"{ user(id: "7") { name reviews { body } } }"#).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({
            "data": { "user": { "name": "Ada", "reviews": [{ "body": "solid" }] } }
        })
    );

    // The users subgraph never saw the foreign field; the reviews subgraph
    // got one `_entities` call carrying the representation.
    let users_seen = users_log.lock().expect("not poisoned").clone();
    assert_eq!(users_seen.len(), 1);
    assert!(
        users_seen[0].contains("g2__id: id"),
        "got: {}",
        users_seen[0]
    );
    assert!(!users_seen[0].contains("reviews"), "got: {}", users_seen[0]);
    let reviews_seen = reviews_log.lock().expect("not poisoned").clone();
    assert_eq!(reviews_seen.len(), 1);
    assert!(
        reviews_seen[0].contains("_entities"),
        "got: {}",
        reviews_seen[0]
    );
    assert!(
        reviews_seen[0].contains(r#"{"__typename":"User","id":"7"}"#),
        "got: {}",
        reviews_seen[0]
    );
}

#[tokio::test]
async fn composed_schema_answers_introspection_locally() {
    let (users, users_log) = spawn_subgraph(users_reply).await;
    let (reviews, _) = spawn_subgraph(reviews_reply).await;
    let (gw, _stop) = spawn_gateway(vec![supergraph_api(users, reviews)]).await;

    let (status, body) = post(
        gw,
        "/fed",
        r#"{ __type(name: "User") { fields { name } } }"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fields: Vec<&str> = body["data"]["__type"]["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .map(|f| f["name"].as_str().expect("name"))
        .collect();
    assert!(fields.contains(&"name") && fields.contains(&"reviews"));
    assert!(
        users_log.lock().expect("not poisoned").is_empty(),
        "no subgraph consulted for introspection"
    );
}

#[tokio::test]
async fn dead_subgraph_degrades_to_partial_data() {
    let (users, _) = spawn_subgraph(users_reply).await;
    // Bind-and-drop a listener so the reviews URL points at a closed port.
    let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let reviews = dead.local_addr().expect("addr");
    drop(dead);
    let (gw, _stop) = spawn_gateway(vec![supergraph_api(users, reviews)]).await;

    let (status, body) = post(gw, "/fed", r#"{ user(id: "7") { name reviews { body } } }"#).await;
    assert_eq!(status, StatusCode::OK, "partial data is a spec 200");
    assert_eq!(body["data"]["user"]["name"], "Ada");
    assert_eq!(body["data"]["user"]["reviews"], serde_json::Value::Null);
    let message = body["errors"][0]["message"].as_str().expect("message");
    assert!(message.contains("`reviews`"), "got: {message}");
    assert!(!message.contains(&reviews.to_string()), "no address leaks");
}

#[tokio::test]
async fn subgraph_mode_forwards_reserved_federation_queries() {
    let (users, users_log) = spawn_subgraph(users_reply).await;
    let def = serde_json::from_str::<ApiDefinition>(
        &serde_json::json!({
            "api_id": "sub-e2e",
            "name": "sub-e2e",
            "listen_path": "/sub/",
            "target_url": format!("http://{users}/graphql"),
            "auth": { "mode": "keyless" },
            "graphql": {
                "execution_mode": "subgraph",
                "schema": USERS_SDL
            }
        })
        .to_string(),
    )
    .expect("definition");
    let (gw, _stop) = spawn_gateway(vec![def]).await;

    // The reserved queries validate against the augmented schema and reach
    // the upstream; an invalid one never does.
    let (status, body) = post(gw, "/sub", "{ _service { sdl } }").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["_service"]["sdl"].is_string(), "got: {body}");
    let (status, _) = post(
        gw,
        "/sub",
        r#"query ($r: [_Any!]!) { _entities(representations: $r) { ... on User { name } } }"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post(gw, "/sub", "{ nonexistent }").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(users_log.lock().expect("not poisoned").len(), 2);
}
