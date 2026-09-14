//! [`PluginLayer`]: WASM pre/post request hooks for one API (ADR-0005).
//!
//! Two instances of this layer sit in the chain: the **pre** slot directly
//! above [`AuthLayer`](crate::AuthLayer) (hooks can inject or transform
//! credentials, and statically-rejected requests — blocked paths, oversized
//! bodies — never buy plugin CPU) and the **post** slot directly below
//! [`RateLimitLayer`](crate::RateLimitLayer) (hooks see the authenticated
//! session, and 401/403/429 rejections never invoke them). Both sit above
//! [`ApiIdHeaderLayer`](crate::ApiIdHeaderLayer), so a plugin can never
//! spoof the anti-spoof api-id header.
//!
//! This crate is deliberately WASM-runtime-free: plugins arrive through the
//! [`PluginExec`] trait, produced by a [`PluginLoader`] at route-build time
//! (the `g2-plugin` crate implements both over wasmtime; tests substitute
//! in-memory fakes — the same inversion as [`JwksFetch`](crate::JwksFetch)).
//!
//! A hook either lets the request continue (optionally mutating request
//! headers, visible to every later plugin and layer) or answers it outright.
//! A failing hook — trap, timeout, malformed output — rejects the request
//! with `500`: plugins fail **closed**, because a hook may itself be a
//! security control (unlike the rate limiter, whose storage errors fail
//! open: there, auth still stands between a broken limiter and the
//! upstream).

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use g2_core::{Error, PluginRef};
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, Service};

use crate::context::{ClientAddr, RequestContext, SessionContext};
use crate::response::json_error;
use crate::ProxyBody;

/// Which hook slot a plugin runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    /// Before authentication.
    Pre,
    /// After authentication and rate limiting.
    Post,
}

impl HookKind {
    /// The wire/config name of the slot (`"pre"` / `"post"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pre => "pre",
            Self::Post => "post",
        }
    }
}

/// Everything a plugin may observe about one request, borrowed from the
/// request being processed.
#[derive(Debug)]
pub struct HookInvocation<'a> {
    /// The slot this invocation runs in.
    pub kind: HookKind,
    /// The owning API.
    pub api_id: &'a str,
    /// The owning organization.
    pub org_id: &'a str,
    /// Request method.
    pub method: &'a Method,
    /// Full client request path, listen path included.
    pub path: &'a str,
    /// Raw query string, without the `?`.
    pub query: Option<&'a str>,
    /// Current request headers (including earlier plugins' mutations).
    pub headers: &'a http::HeaderMap,
    /// The client's socket address, when known.
    pub client_addr: Option<SocketAddr>,
    /// The authenticated session's alias — post hooks on authenticated
    /// requests only.
    pub session_alias: Option<&'a str>,
}

/// What a plugin decided about one request.
#[derive(Debug)]
pub enum HookOutcome {
    /// Let the request continue, after applying the header mutations
    /// (removals first, then insert-replace sets).
    Continue {
        /// Headers to set on the request (insert semantics: an existing
        /// header of the same name is replaced).
        set_headers: Vec<(HeaderName, HeaderValue)>,
        /// Headers to remove from the request.
        remove_headers: Vec<HeaderName>,
    },
    /// Answer the request with this response; nothing further runs.
    Respond(Response<Bytes>),
}

/// One loaded plugin, callable per request.
///
/// Implementations must be cheap to call concurrently (`&self`) and bound
/// their own execution: the layer calls [`PluginExec::run`] inline on the
/// serving task.
pub trait PluginExec: Send + Sync + 'static {
    /// The plugin's configured name, for logs and error messages.
    fn name(&self) -> &str;

    /// Runs the hook against one request.
    ///
    /// # Errors
    ///
    /// Any failure — trap, timeout, resource cap, malformed guest output —
    /// is a plain string; the layer logs it and fails the request closed.
    fn run(&self, call: &HookInvocation<'_>) -> Result<HookOutcome, String>;
}

/// Shared handle to a loaded plugin.
pub type SharedPluginExec = Arc<dyn PluginExec>;

/// Turns a [`PluginRef`] into a loaded [`PluginExec`] at route-build time.
///
/// Implemented by the `g2-plugin` crate over wasmtime (compile + link +
/// export checks); tests substitute fakes. Errors are plain strings that
/// the router wraps into [`Error::InvalidApiDefinition`], so a broken
/// module fails a (re)build loudly and a hot reload keeps the old table.
pub trait PluginLoader: Send + Sync + 'static {
    /// Loads the module referenced by `plugin` for the given API and slot.
    ///
    /// # Errors
    ///
    /// Returns a description of what failed (missing file, compile error,
    /// missing export, ABI mismatch).
    fn load(
        &self,
        api_id: &str,
        hook: HookKind,
        plugin: &PluginRef,
    ) -> Result<SharedPluginExec, String>;
}

/// Shared loader handle threaded through the route build.
pub type SharedPluginLoader = Arc<dyn PluginLoader>;

/// Tower layer running one API's plugin list for one hook slot.
#[derive(Clone)]
pub struct PluginLayer {
    shared: Arc<PluginShared>,
}

struct PluginShared {
    kind: HookKind,
    plugins: Box<[SharedPluginExec]>,
}

impl std::fmt::Debug for PluginLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginLayer")
            .field("kind", &self.shared.kind)
            .field("plugins", &self.shared.plugins.len())
            .finish()
    }
}

impl PluginLayer {
    /// Loads `refs` through `loader` into a layer, or `None` when there are
    /// none (the API gets no plugin layer in this slot).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a plugin fails to load,
    /// or when plugins are configured but the gateway has no loader (no
    /// `plugins_dir` configured).
    pub fn from_config(
        kind: HookKind,
        refs: &[PluginRef],
        loader: Option<&SharedPluginLoader>,
        api_id: &str,
    ) -> Result<Option<Self>, Error> {
        if refs.is_empty() {
            return Ok(None);
        }
        let Some(loader) = loader else {
            return Err(Error::InvalidApiDefinition {
                api: api_id.to_owned(),
                reason: "definition declares `plugins` but the gateway has no plugins \
                         directory configured (start it with `--plugins-dir`)"
                    .to_owned(),
            });
        };
        let plugins = refs
            .iter()
            .map(|r| {
                loader
                    .load(api_id, kind, r)
                    .map_err(|reason| Error::InvalidApiDefinition {
                        api: api_id.to_owned(),
                        reason: format!("plugin `{}` failed to load: {reason}", r.name),
                    })
            })
            .collect::<Result<Box<[_]>, _>>()?;
        Ok(Some(Self {
            shared: Arc::new(PluginShared { kind, plugins }),
        }))
    }

    /// Builds a layer directly from loaded plugins (tests).
    #[must_use]
    pub fn from_execs(kind: HookKind, plugins: Vec<SharedPluginExec>) -> Self {
        Self {
            shared: Arc::new(PluginShared {
                kind,
                plugins: plugins.into(),
            }),
        }
    }
}

impl<S> Layer<S> for PluginLayer {
    type Service = Plugin<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Plugin {
            inner,
            shared: Arc::clone(&self.shared),
        }
    }
}

/// The [`Service`] produced by [`PluginLayer`].
#[derive(Clone)]
pub struct Plugin<S> {
    inner: S,
    shared: Arc<PluginShared>,
}

impl<S> std::fmt::Debug for Plugin<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("kind", &self.shared.kind)
            .finish_non_exhaustive()
    }
}

impl<S> Service<Request<ProxyBody>> for Plugin<S>
where
    S: Service<Request<ProxyBody>, Response = Response<ProxyBody>, Error = Infallible>
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ProxyBody>) -> Self::Future {
        let shared = Arc::clone(&self.shared);
        // Run the plugins before touching `inner`: they are synchronous, and
        // a short-circuit or failure must not consume the inner service's
        // readiness.
        for exec in shared.plugins.iter() {
            match run_one(&shared, exec.as_ref(), &req) {
                Ok(HookOutcome::Continue {
                    set_headers,
                    remove_headers,
                }) => {
                    let headers = req.headers_mut();
                    for name in &remove_headers {
                        headers.remove(name);
                    }
                    for (name, value) in set_headers {
                        headers.insert(name, value);
                    }
                }
                Ok(HookOutcome::Respond(resp)) => {
                    let (parts, body) = resp.into_parts();
                    let resp = Response::from_parts(parts, ProxyBody::new(Full::new(body)));
                    return Box::pin(std::future::ready(Ok(resp)));
                }
                Err(reason) => {
                    tracing::error!(
                        plugin = exec.name(),
                        hook = shared.kind.as_str(),
                        error = %reason,
                        "plugin failed; rejecting request (plugins fail closed)"
                    );
                    return Box::pin(std::future::ready(Ok(json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "plugin execution failed",
                    ))));
                }
            }
        }
        Box::pin(self.inner.call(req))
    }
}

/// Builds the invocation view for one plugin call and runs it.
fn run_one(
    shared: &PluginShared,
    exec: &dyn PluginExec,
    req: &Request<ProxyBody>,
) -> Result<HookOutcome, String> {
    let ctx = req.extensions().get::<RequestContext>();
    let session_alias = match shared.kind {
        HookKind::Pre => None,
        HookKind::Post => req
            .extensions()
            .get::<SessionContext>()
            .and_then(|s| s.session().alias.as_deref()),
    };
    let call = HookInvocation {
        kind: shared.kind,
        api_id: ctx.map_or("", RequestContext::api_id),
        org_id: ctx.map_or("", RequestContext::org_id),
        method: req.method(),
        path: req.uri().path(),
        query: req.uri().query(),
        headers: req.headers(),
        client_addr: req.extensions().get::<ClientAddr>().map(|a| a.0),
        session_alias,
    };
    exec.run(&call)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    /// Inner stand-in for the forwarder: 200 echoing the request headers.
    async fn upstream(req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let mut resp = Response::new(body());
        resp.headers_mut()
            .insert("x-upstream", HeaderValue::from_static("1"));
        for (name, value) in req.headers() {
            resp.headers_mut().insert(name.clone(), value.clone());
        }
        Ok(resp)
    }

    type OutcomeFn = Box<dyn Fn(&HookInvocation<'_>) -> Result<HookOutcome, String> + Send + Sync>;

    /// Scripted fake plugin recording what it saw.
    struct FakeExec {
        name: String,
        outcome: OutcomeFn,
        calls: AtomicUsize,
        seen: Mutex<Vec<String>>,
    }

    impl FakeExec {
        fn new(
            name: &str,
            outcome: impl Fn(&HookInvocation<'_>) -> Result<HookOutcome, String> + Send + Sync + 'static,
        ) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_owned(),
                outcome: Box::new(outcome),
                calls: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
            })
        }
    }

    impl PluginExec for FakeExec {
        fn name(&self) -> &str {
            &self.name
        }

        fn run(&self, call: &HookInvocation<'_>) -> Result<HookOutcome, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().expect("lock").push(format!(
                "{} {}{}",
                call.method,
                call.path,
                call.headers
                    .get("x-tag")
                    .map(|v| format!(" x-tag={}", v.to_str().expect("ascii")))
                    .unwrap_or_default()
            ));
            (self.outcome)(call)
        }
    }

    fn continue_with(set: &[(&str, &str)], remove: &[&str]) -> HookOutcome {
        HookOutcome::Continue {
            set_headers: set
                .iter()
                .map(|(n, v)| {
                    (
                        HeaderName::try_from(*n).expect("name"),
                        HeaderValue::try_from(*v).expect("value"),
                    )
                })
                .collect(),
            remove_headers: remove
                .iter()
                .map(|n| HeaderName::try_from(*n).expect("name"))
                .collect(),
        }
    }

    async fn call_layer(layer: &PluginLayer, req: Request<ProxyBody>) -> Response<ProxyBody> {
        layer
            .clone()
            .layer(tower::service_fn(upstream))
            .oneshot(req)
            .await
            .expect("infallible")
    }

    fn request() -> Request<ProxyBody> {
        let mut req = Request::builder()
            .method("GET")
            .uri("/api/users?page=2")
            .header("x-tag", "original")
            .body(body())
            .expect("request");
        req.extensions_mut()
            .insert(RequestContext::new("api-1", "org-1"));
        req
    }

    #[test]
    fn empty_refs_build_no_layer() {
        let layer = PluginLayer::from_config(HookKind::Pre, &[], None, "api").expect("ok");
        assert!(layer.is_none());
    }

    #[test]
    fn refs_without_a_loader_fail_the_build() {
        let refs: Vec<PluginRef> =
            serde_json::from_str(r#"[{"name":"a","path":"a.wasm"}]"#).expect("refs");
        let err = PluginLayer::from_config(HookKind::Pre, &refs, None, "api").unwrap_err();
        assert!(err.to_string().contains("--plugins-dir"), "{err}");
    }

    #[tokio::test]
    async fn continue_mutations_reach_the_upstream() {
        let exec = FakeExec::new("mutator", |_| {
            Ok(continue_with(&[("x-from-plugin", "yes")], &["x-tag"]))
        });
        let layer = PluginLayer::from_execs(HookKind::Pre, vec![exec]);
        let resp = call_layer(&layer, request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-from-plugin").expect("set"),
            "yes",
            "set header forwarded"
        );
        assert!(
            resp.headers().get("x-tag").is_none(),
            "removed header not forwarded"
        );
        assert!(resp.headers().get("x-upstream").is_some());
    }

    #[tokio::test]
    async fn respond_short_circuits_the_chain() {
        let exec = FakeExec::new("guard", |_| {
            let mut resp = Response::new(Bytes::from_static(b"denied"));
            *resp.status_mut() = StatusCode::FORBIDDEN;
            resp.headers_mut()
                .insert("x-guard", HeaderValue::from_static("1"));
            Ok(HookOutcome::Respond(resp))
        });
        let layer = PluginLayer::from_execs(HookKind::Pre, vec![exec]);
        let resp = call_layer(&layer, request()).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers().get("x-guard").expect("set"), "1");
        assert!(
            resp.headers().get("x-upstream").is_none(),
            "upstream must not run after a short-circuit"
        );
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(bytes.as_ref(), b"denied");
    }

    #[tokio::test]
    async fn plugin_error_fails_closed_with_500() {
        let failing = FakeExec::new("broken", |_| Err("guest trapped".to_owned()));
        let after = FakeExec::new("after", |_| Ok(continue_with(&[], &[])));
        let layer = PluginLayer::from_execs(
            HookKind::Pre,
            vec![failing, Arc::clone(&after) as SharedPluginExec],
        );
        let resp = call_layer(&layer, request()).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get("x-upstream").is_none());
        assert_eq!(
            after.calls.load(Ordering::SeqCst),
            0,
            "later plugins must not run after a failure"
        );
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(bytes.as_ref(), br#"{"error":"plugin execution failed"}"#);
    }

    #[tokio::test]
    async fn plugins_run_in_order_and_see_earlier_mutations() {
        let first = FakeExec::new("first", |_| {
            Ok(continue_with(&[("x-tag", "rewritten")], &[]))
        });
        let second = FakeExec::new("second", |_| Ok(continue_with(&[], &[])));
        let layer = PluginLayer::from_execs(
            HookKind::Pre,
            vec![
                Arc::clone(&first) as SharedPluginExec,
                Arc::clone(&second) as SharedPluginExec,
            ],
        );
        let resp = call_layer(&layer, request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            second.seen.lock().expect("lock").as_slice(),
            ["GET /api/users x-tag=rewritten"],
            "second plugin sees the first's mutation, method and full path"
        );
        assert_eq!(first.calls.load(Ordering::SeqCst), 1);
    }

    type SeenContext = (String, String, Option<String>, Option<String>);

    #[tokio::test]
    async fn invocation_carries_context_and_query() {
        let seen: Arc<Mutex<Option<SeenContext>>> = Arc::new(Mutex::new(None));
        let seen_in = Arc::clone(&seen);
        let exec = FakeExec::new("inspect", move |call| {
            *seen_in.lock().expect("lock") = Some((
                call.api_id.to_owned(),
                call.org_id.to_owned(),
                call.query.map(str::to_owned),
                call.session_alias.map(str::to_owned),
            ));
            Ok(continue_with(&[], &[]))
        });
        let layer = PluginLayer::from_execs(HookKind::Pre, vec![exec]);
        call_layer(&layer, request()).await;
        let got = seen.lock().expect("lock").take().expect("called");
        assert_eq!(
            got,
            (
                "api-1".to_owned(),
                "org-1".to_owned(),
                Some("page=2".to_owned()),
                None
            )
        );
    }

    #[tokio::test]
    async fn post_hook_reads_the_session_alias() {
        let seen: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));
        let seen_in = Arc::clone(&seen);
        let exec = FakeExec::new("inspect", move |call| {
            *seen_in.lock().expect("lock") = Some(call.session_alias.map(str::to_owned));
            Ok(continue_with(&[], &[]))
        });
        let layer = PluginLayer::from_execs(HookKind::Post, vec![exec]);
        let mut req = request();
        let session: g2_core::KeySession =
            serde_json::from_str(r#"{"alias":"acme"}"#).expect("session");
        req.extensions_mut()
            .insert(SessionContext::new(session, "hash"));
        call_layer(&layer, req).await;
        assert_eq!(
            seen.lock().expect("lock").take().expect("called"),
            Some("acme".to_owned())
        );
    }
}
