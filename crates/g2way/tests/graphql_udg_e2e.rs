//! End-to-end Universal Data Graph tests: a real g2way server executing
//! GraphQL queries by stitching REST and GraphQL upstreams over TCP
//! (milestone M9, ADR-0010).

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

/// One request an upstream saw: method, path, the `x-tag` header (if any),
/// and the raw body.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    tag: Option<String>,
    body: String,
}

type SeenLog = Arc<Mutex<Vec<Seen>>>;

/// Spawns a fake REST upstream serving JSON by path: `/hello` → `"hi"`,
/// `/users/{id}` → a user object with a nested friend, `/fail` → `500`.
/// Every request is recorded.
async fn spawn_rest_upstream() -> (SocketAddr, SeenLog) {
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
                        let path = req.uri().path().to_owned();
                        let seen = Seen {
                            method: req.method().to_string(),
                            path: path.clone(),
                            tag: req
                                .headers()
                                .get("x-tag")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned),
                            body: String::from_utf8_lossy(
                                &req.collect().await.expect("body").to_bytes(),
                            )
                            .into_owned(),
                        };
                        log.lock().expect("not poisoned").push(seen);
                        let (status, body) = if path == "/hello" {
                            (StatusCode::OK, "\"hi\"".to_owned())
                        } else if let Some(id) = path.strip_prefix("/users/") {
                            (
                                StatusCode::OK,
                                serde_json::json!({
                                    "id": id,
                                    "name": format!("user-{id}"),
                                    "friend": { "id": "f1", "name": "buddy" },
                                    "internal": true
                                })
                                .to_string(),
                            )
                        } else {
                            (StatusCode::INTERNAL_SERVER_ERROR, "boom".to_owned())
                        };
                        let mut resp = Response::new(Full::new(Bytes::from(body)));
                        *resp.status_mut() = status;
                        Ok::<_, std::convert::Infallible>(resp)
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

/// Spawns a fake GraphQL upstream: every `POST` is recorded and answered
/// with a fixed alias-keyed payload plus one error.
async fn spawn_graphql_upstream() -> (SocketAddr, SeenLog) {
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
                        let seen = Seen {
                            method: req.method().to_string(),
                            path: req.uri().path().to_owned(),
                            tag: None,
                            body: String::from_utf8_lossy(
                                &req.collect().await.expect("body").to_bytes(),
                            )
                            .into_owned(),
                        };
                        let reply = if seen.body.contains("\"r: remote\"")
                            || seen.body.contains("r: remote")
                        {
                            r#"{"data":{"r":{"id":"9","name":"Ada"}},"errors":[{"message":"deprecated"}]}"#
                        } else {
                            r#"{"data":{"remote":{"id":"9","name":"Ada"}}}"#
                        };
                        log.lock().expect("not poisoned").push(seen);
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            reply,
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

/// A keyless UDG API stitching the REST upstream (`hello`, `user`,
/// `broken`) and the GraphQL upstream (`remote`).
fn udg_api(rest: SocketAddr, gql: SocketAddr) -> ApiDefinition {
    serde_json::from_str::<ApiDefinition>(
        &serde_json::json!({
            "api_id": "udg-e2e",
            "name": "udg-e2e",
            "listen_path": "/udg/",
            "target_url": "http://unused.invalid/",
            "auth": { "mode": "keyless" },
            "graphql": {
                "schema": "type Query { hello: String user(id: ID!): User \
                           broken: Int remote: User } \
                           type User { id: ID! name: String friend: User }",
                "execution_mode": "udg",
                "max_query_depth": 3,
                "persisted_queries": [{
                    "method": "GET",
                    "path": "/u/{id}",
                    "operation": "query U($id: ID!) { user(id: $id) { name } }",
                    "variables": { "id": "$path.id" }
                }],
                "data_sources": {
                    "Query.hello": {
                        "kind": "rest",
                        "url": format!("http://{rest}/hello")
                    },
                    "Query.user": {
                        "kind": "rest",
                        "url": format!("http://{rest}/users/{{{{ args.id }}}}"),
                        "headers": { "x-tag": "{{ _g2.headers['x-tag'] }}" }
                    },
                    "Query.broken": {
                        "kind": "rest",
                        "url": format!("http://{rest}/fail")
                    },
                    "Query.remote": {
                        "kind": "graphql",
                        "url": format!("http://{gql}/graphql")
                    }
                }
            }
        })
        .to_string(),
    )
    .expect("definition")
}

async fn send(
    gw: SocketAddr,
    method: Method,
    path_and_query: &str,
    body: &str,
    tag: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://{gw}{path_and_query}"));
    if let Some(tag) = tag {
        builder = builder.header("x-tag", tag);
    }
    let req = builder
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("request");
    let resp = client.request(req).await.expect("gateway reachable");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!(String::from_utf8_lossy(&bytes)));
    (status, json)
}

fn query_body(query: &str) -> String {
    serde_json::json!({ "query": query }).to_string()
}

#[tokio::test]
async fn stitches_rest_sources_with_templates_and_nested_projection() {
    let (rest, log) = spawn_rest_upstream().await;
    let (gql, _glog) = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![udg_api(rest, gql)]).await;

    let (status, body) = send(
        gw,
        Method::POST,
        "/udg/",
        &query_body(r#"{ greeting: hello user(id: "7") { name friend { name } } }"#),
        Some("trace-1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert_eq!(
        body,
        serde_json::json!({
            "data": {
                "greeting": "hi",
                "user": { "name": "user-7", "friend": { "name": "buddy" } }
            }
        }),
        "aliases honored, extras pruned, nested object projected"
    );

    let seen = log.lock().expect("not poisoned").clone();
    let user_call = seen
        .iter()
        .find(|s| s.path == "/users/7")
        .expect("templated URL reached the upstream");
    assert_eq!(user_call.method, "GET");
    assert_eq!(
        user_call.tag.as_deref(),
        Some("trace-1"),
        "client header reached the source via the _g2 template"
    );
}

#[tokio::test]
async fn graphql_source_gets_the_subquery_and_its_errors_surface() {
    let (rest, _log) = spawn_rest_upstream().await;
    let (gql, glog) = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![udg_api(rest, gql)]).await;

    let (status, body) = send(
        gw,
        Method::POST,
        "/udg/",
        &query_body("{ r: remote { name } }"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert_eq!(body["data"]["r"], serde_json::json!({ "name": "Ada" }));
    let messages = body["errors"]
        .as_array()
        .expect("errors present")
        .iter()
        .map(|e| e["message"].as_str().unwrap_or("").to_owned())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(messages.contains("deprecated"), "got: {messages}");

    let seen = glog.lock().expect("not poisoned").clone();
    assert_eq!(seen.len(), 1, "one sub-query sent");
    let envelope: serde_json::Value =
        serde_json::from_str(&seen[0].body).expect("upstream got JSON");
    let sub_query = envelope["query"].as_str().expect("query text");
    assert!(
        sub_query.contains("r: remote"),
        "alias round-trips: {sub_query}"
    );
    assert!(
        !sub_query.contains("hello"),
        "other root fields stay home: {sub_query}"
    );
}

#[tokio::test]
async fn failed_source_yields_partial_data_and_a_redacted_error() {
    let (rest, _log) = spawn_rest_upstream().await;
    let (gql, _glog) = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![udg_api(rest, gql)]).await;

    let (status, body) = send(
        gw,
        Method::POST,
        "/udg/",
        &query_body("{ hello broken }"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "spec: field errors are 200s; got {body}"
    );
    assert_eq!(body["data"]["hello"], "hi");
    assert_eq!(body["data"]["broken"], serde_json::Value::Null);
    let message = body["errors"][0]["message"].as_str().expect("message");
    assert!(message.contains("`Query.broken`"), "got: {message}");
    assert!(
        !message.contains("boom") && !message.contains("/fail"),
        "upstream detail redacted: {message}"
    );
    assert_eq!(body["errors"][0]["path"], serde_json::json!(["broken"]));
}

#[tokio::test]
async fn introspection_is_served_without_touching_upstreams() {
    let (rest, log) = spawn_rest_upstream().await;
    let (gql, glog) = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![udg_api(rest, gql)]).await;

    let (status, body) = send(
        gw,
        Method::POST,
        "/udg/",
        &query_body("{ __schema { queryType { name } } }"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert_eq!(body["data"]["__schema"]["queryType"]["name"], "Query");
    assert!(log.lock().expect("not poisoned").is_empty());
    assert!(glog.lock().expect("not poisoned").is_empty());
}

#[tokio::test]
async fn persisted_endpoints_execute_locally() {
    let (rest, log) = spawn_rest_upstream().await;
    let (gql, _glog) = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![udg_api(rest, gql)]).await;

    let (status, body) = send(gw, Method::GET, "/udg/u/42", "", None).await;
    assert_eq!(status, StatusCode::OK, "got: {body}");
    assert_eq!(
        body["data"]["user"],
        serde_json::json!({ "name": "user-42" })
    );
    let seen = log.lock().expect("not poisoned").clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].path, "/users/42",
        "path parameter reached the source"
    );
}

#[tokio::test]
async fn protections_reject_before_any_fetch() {
    let (rest, log) = spawn_rest_upstream().await;
    let (gql, glog) = spawn_graphql_upstream().await;
    let (gw, _stop) = spawn_gateway(vec![udg_api(rest, gql)]).await;

    // Depth 4 > the API's limit of 3.
    let (status, body) = send(
        gw,
        Method::POST,
        "/udg/",
        &query_body(r#"{ user(id: "1") { friend { friend { name } } } }"#),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got: {body}");
    assert!(log.lock().expect("not poisoned").is_empty());
    assert!(glog.lock().expect("not poisoned").is_empty());
}
