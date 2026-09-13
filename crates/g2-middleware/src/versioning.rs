//! [`VersionDispatch`]: routes a request to the chain of its API version.
//!
//! A versioned API keeps one prebuilt inner chain per version (each built
//! from the version's effective definition — see
//! [`VersioningConfig::apply`]). This service sits between the shared outer
//! layers (trace → CORS, composed with
//! [`ChainBuilder::build_outer`](crate::ChainBuilder::build_outer)) and
//! those per-version chains (composed with
//! [`ChainBuilder::build_inner`](crate::ChainBuilder::build_inner)): it
//! reads the requested version name from the configured header or query
//! parameter, falls back to the default version when the request names
//! none, and dispatches. A request that resolves to no version, an unknown
//! version, or an expired version is rejected with `403` —
//! and, sitting below the outer layers, that rejection is still counted,
//! recorded, and CORS-decorated like any other gateway rejection.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use g2_core::versioning::{VersionLocation, VersioningConfig};
use g2_core::Error;
use http::{HeaderName, Request, Response, StatusCode};
use tower::{Service, ServiceExt};

use crate::auth::unix_now_secs;
use crate::response::json_error;
use crate::{ChainService, ProxyBody};

/// Where the requested version name is read from, precompiled at
/// route-build time.
#[derive(Debug, Clone)]
enum VersionSelector {
    /// A request header, by precompiled name.
    Header(HeaderName),
    /// A query parameter, matched verbatim (no percent-decoding) like the
    /// auth-token query carrier.
    QueryParam(String),
}

/// One dispatchable version: its prebuilt chain and expiry.
struct VersionSlot {
    chain: ChainService,
    expires_at: Option<u64>,
}

struct Inner {
    api_id: String,
    selector: VersionSelector,
    default_version: Option<String>,
    versions: HashMap<String, VersionSlot>,
}

/// The version-dispatching service of one versioned API (see the module
/// docs). Cheap to clone: clones share the per-version chains.
#[derive(Clone)]
pub struct VersionDispatch {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for VersionDispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionDispatch")
            .field("api_id", &self.inner.api_id)
            .field("selector", &self.inner.selector)
            .field("default_version", &self.inner.default_version)
            .field("versions", &self.inner.versions.keys())
            .finish()
    }
}

impl VersionDispatch {
    /// Builds the dispatcher for `config`, taking ownership of the prebuilt
    /// per-version `chains` (keyed by version name).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when the configured header
    /// name is invalid (already rejected by config validation) or `chains`
    /// is missing a configured version — both indicate a route-build bug,
    /// surfaced as a load error rather than a panic.
    pub fn from_config(
        config: &VersioningConfig,
        mut chains: HashMap<String, ChainService>,
        api_id: &str,
    ) -> Result<Self, Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api_id.to_owned(),
            reason,
        };
        let selector = match config.location {
            VersionLocation::Header => VersionSelector::Header(
                HeaderName::from_bytes(config.key.as_bytes()).map_err(|_| {
                    fail(format!(
                        "`versioning.key` is not a valid header name: `{}`",
                        config.key
                    ))
                })?,
            ),
            VersionLocation::QueryParam => VersionSelector::QueryParam(config.key.clone()),
        };
        let mut versions = HashMap::with_capacity(config.versions.len());
        for (name, overrides) in &config.versions {
            let chain = chains
                .remove(name)
                .ok_or_else(|| fail(format!("no chain was built for version `{name}`")))?;
            versions.insert(
                name.clone(),
                VersionSlot {
                    chain,
                    expires_at: overrides.expires_at,
                },
            );
        }
        Ok(Self {
            inner: Arc::new(Inner {
                api_id: api_id.to_owned(),
                selector,
                default_version: config.default_version.clone(),
                versions,
            }),
        })
    }

    /// The version name the request asks for, if any (trimmed, non-empty).
    fn requested<B>(&self, req: &Request<B>) -> Option<String> {
        match &self.inner.selector {
            VersionSelector::Header(name) => req
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_owned()),
            VersionSelector::QueryParam(param) => req.uri().query().and_then(|query| {
                query.split('&').find_map(|pair| {
                    pair.split_once('=')
                        .filter(|(k, _)| k == param)
                        .map(|(_, v)| v.trim().to_owned())
                })
            }),
        }
        .filter(|name| !name.is_empty())
    }
}

impl Service<Request<ProxyBody>> for VersionDispatch {
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<ProxyBody>, Infallible>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<ProxyBody>) -> Self::Future {
        let api_id = self.inner.api_id.as_str();
        let Some(name) = self
            .requested(&req)
            .or_else(|| self.inner.default_version.clone())
        else {
            tracing::debug!(%api_id, "request names no version and the API has no default");
            return reject("version information not found");
        };
        let Some(slot) = self.inner.versions.get(&name) else {
            tracing::debug!(%api_id, version = %name, "requested version does not exist");
            return reject("requested API version does not exist");
        };
        // Inclusive boundary, matching key-session expiry.
        if slot.expires_at.is_some_and(|at| at <= unix_now_secs()) {
            tracing::debug!(%api_id, version = %name, "requested version has expired");
            return reject("requested API version has expired");
        }
        let chain = slot.chain.clone();
        Box::pin(chain.oneshot(req))
    }
}

/// A ready future answering `403` with `message`.
fn reject(
    message: &str,
) -> Pin<Box<dyn Future<Output = Result<Response<ProxyBody>, Infallible>> + Send + 'static>> {
    let resp = json_error(StatusCode::FORBIDDEN, message);
    Box::pin(std::future::ready(Ok(resp)))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use tower::util::BoxCloneSyncService;

    use super::*;
    use crate::chain::ChainBuilder;

    fn versioning(json: &str) -> VersioningConfig {
        serde_json::from_str(json).expect("valid versioning JSON")
    }

    /// A chain stand-in answering 200 with `label` as the body.
    fn labeled_chain(label: &'static str) -> ChainService {
        BoxCloneSyncService::new(tower::service_fn(move |_req: Request<ProxyBody>| async {
            Ok::<_, Infallible>(Response::new(ProxyBody::new(Full::new(
                Bytes::from_static(label.as_bytes()),
            ))))
        }))
    }

    fn dispatch(config_json: &str, chains: Vec<(&str, ChainService)>) -> VersionDispatch {
        let chains = chains
            .into_iter()
            .map(|(name, chain)| (name.to_owned(), chain))
            .collect();
        VersionDispatch::from_config(&versioning(config_json), chains, "vapi").expect("builds")
    }

    async fn body_of(resp: Response<ProxyBody>) -> String {
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    fn get(uri: &str) -> Request<ProxyBody> {
        Request::builder()
            .uri(uri)
            .body(ProxyBody::empty())
            .expect("request")
    }

    #[tokio::test]
    async fn header_selection_dispatches_to_the_named_version() {
        let svc = dispatch(
            r#"{"versions": {"v1": {}, "v2": {}}}"#,
            vec![("v1", labeled_chain("one")), ("v2", labeled_chain("two"))],
        );

        let mut req = get("/x");
        req.headers_mut()
            .insert("x-api-version", "v2".parse().expect("value"));
        let resp = svc.clone().oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, "two");

        // Padded values are trimmed before matching.
        let mut req = get("/x");
        req.headers_mut()
            .insert("x-api-version", " v1 ".parse().expect("value"));
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(body_of(resp).await, "one");
    }

    #[tokio::test]
    async fn query_param_selection_works() {
        let svc = dispatch(
            r#"{"location": "query_param", "key": "version", "versions": {"v1": {}}}"#,
            vec![("v1", labeled_chain("one"))],
        );
        let resp = svc
            .oneshot(get("/x?a=b&version=v1"))
            .await
            .expect("infallible");
        assert_eq!(body_of(resp).await, "one");
    }

    #[tokio::test]
    async fn missing_version_uses_the_default_or_403s() {
        let with_default = dispatch(
            r#"{"default_version": "v1", "versions": {"v1": {}}}"#,
            vec![("v1", labeled_chain("one"))],
        );
        let resp = with_default.oneshot(get("/x")).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::OK);

        let without_default = dispatch(
            r#"{"versions": {"v1": {}}}"#,
            vec![("v1", labeled_chain("one"))],
        );
        let resp = without_default
            .oneshot(get("/x"))
            .await
            .expect("infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_of(resp)
            .await
            .contains("version information not found"));
    }

    #[tokio::test]
    async fn unknown_and_expired_versions_are_rejected() {
        let svc = dispatch(
            r#"{"versions": {"v1": {}, "old": {"expires_at": 1}}}"#,
            vec![("v1", labeled_chain("one")), ("old", labeled_chain("old"))],
        );

        let mut req = get("/x");
        req.headers_mut()
            .insert("x-api-version", "v9".parse().expect("value"));
        let resp = svc.clone().oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_of(resp).await.contains("does not exist"));

        let mut req = get("/x");
        req.headers_mut()
            .insert("x-api-version", "old".parse().expect("value"));
        let resp = svc.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_of(resp).await.contains("expired"));
    }

    #[tokio::test]
    async fn missing_chain_for_a_configured_version_is_a_build_error() {
        let err = VersionDispatch::from_config(
            &versioning(r#"{"versions": {"v1": {}}}"#),
            HashMap::new(),
            "vapi",
        )
        .expect_err("missing chain");
        assert!(err.to_string().contains("v1"), "got: {err}");
    }

    #[tokio::test]
    async fn version_403_passes_through_the_outer_layers() {
        use g2_core::CorsConfig;

        use crate::context::RequestContext;
        use crate::cors::CorsLayer;

        // A versioned API's outer chain (here: CORS) wraps the dispatcher,
        // so a version rejection is still CORS-decorated for browsers.
        let dispatch = dispatch(
            r#"{"versions": {"v1": {}}}"#,
            vec![("v1", labeled_chain("one"))],
        );
        let cors: CorsConfig =
            serde_json::from_str(r#"{"allowed_origins": ["https://app.example.com"]}"#)
                .expect("valid CORS JSON");
        let chain = ChainBuilder::new(RequestContext::new("vapi", "acme"))
            .cors(Some(
                CorsLayer::from_config(&cors, "vapi").expect("compiles"),
            ))
            .build_outer(dispatch);

        let mut req = get("/x");
        req.headers_mut()
            .insert("origin", "https://app.example.com".parse().expect("value"));
        let resp = chain.oneshot(req).await.expect("infallible");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get("access-control-allow-origin")
                .expect("cors on version rejection")
                .as_bytes(),
            b"https://app.example.com"
        );
    }
}
