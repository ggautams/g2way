//! [`CorsLayer`]: per-API Cross-Origin Resource Sharing handling.
//!
//! Sits below the IP filter (a blocked client gets nothing) and **above**
//! path policy and auth, for two reasons: preflight `OPTIONS` requests are
//! answered by the gateway before any credential work (browsers do not send
//! credentials on preflights), and gateway rejections (`401`/`403`/`429`)
//! are decorated with CORS headers so cross-origin scripts can actually
//! read them.
//!
//! CORS is not access control: a request from an unlisted origin is still
//! forwarded, just without `Access-Control-*` headers — the browser is the
//! enforcement point. Everything is precompiled at
//! route-build time; the hot path compares prebuilt strings and clones
//! cheap [`HeaderValue`] handles (ADR-0001).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use g2_core::{CorsConfig, Error};
use http::header::{
    HeaderMap, HeaderValue, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
    ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
    VARY,
};
use http::{Method, Request, Response, StatusCode};
use tower::{Layer, Service};

use crate::ProxyBody;

/// `Vary` value for preflight responses: everything the answer depends on.
const PREFLIGHT_VARY: HeaderValue = HeaderValue::from_static(
    "origin, access-control-request-method, access-control-request-headers",
);

/// One API's precompiled CORS policy, shared by every clone of the service.
#[derive(Debug)]
struct CorsState {
    /// `allowed_origins` was `["*"]`.
    wildcard: bool,
    /// Explicit origins, ASCII-lowercased for case-insensitive comparison.
    origins: Vec<String>,
    /// Methods allowed on preflight (`Access-Control-Request-Method`).
    allowed_methods: Vec<Method>,
    /// Prebuilt `Access-Control-Allow-Methods` value.
    allow_methods_value: HeaderValue,
    /// Prebuilt `Access-Control-Allow-Headers` value; `None` mirrors the
    /// preflight's requested headers instead.
    allow_headers_value: Option<HeaderValue>,
    /// Lowercased allowed header names (preflight check); empty = any.
    allowed_headers_lower: Vec<String>,
    /// Prebuilt `Access-Control-Expose-Headers` value.
    expose_headers_value: Option<HeaderValue>,
    /// Whether `Access-Control-Allow-Credentials: true` is sent.
    credentials: bool,
    /// Prebuilt `Access-Control-Max-Age` value.
    max_age: Option<HeaderValue>,
    /// Forward preflights upstream instead of answering them.
    options_passthrough: bool,
}

impl CorsState {
    /// Whether `origin` (the raw request header value) is allowed.
    fn origin_allowed(&self, origin: &HeaderValue) -> bool {
        if self.wildcard {
            return true;
        }
        let Ok(origin) = origin.to_str() else {
            return false;
        };
        self.origins.iter().any(|o| o.eq_ignore_ascii_case(origin))
    }

    /// The `Access-Control-Allow-Origin` value for an allowed `origin`.
    fn allow_origin_value(&self, origin: &HeaderValue) -> HeaderValue {
        if self.wildcard {
            HeaderValue::from_static("*")
        } else {
            origin.clone()
        }
    }

    /// Builds the gateway's answer to a preflight request.
    fn preflight_response(
        &self,
        req: &Request<ProxyBody>,
        origin: &HeaderValue,
    ) -> Response<ProxyBody> {
        let mut resp = Response::new(ProxyBody::empty());
        *resp.status_mut() = StatusCode::NO_CONTENT;
        let headers = resp.headers_mut();
        headers.insert(VARY, PREFLIGHT_VARY);

        // A preflight failing any check is answered without CORS headers;
        // the browser then fails the cross-origin request. The gateway
        // stays a 204 either way — enforcement is the browser's job.
        if !self.origin_allowed(origin)
            || !self.preflight_method_allowed(req.headers())
            || !self.preflight_headers_allowed(req.headers())
        {
            return resp;
        }

        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, self.allow_origin_value(origin));
        headers.insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            self.allow_methods_value.clone(),
        );
        let allow_headers = self.allow_headers_value.clone().or_else(|| {
            // No configured list: mirror whatever the preflight asked for.
            req.headers().get(ACCESS_CONTROL_REQUEST_HEADERS).cloned()
        });
        if let Some(value) = allow_headers {
            headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, value);
        }
        if self.credentials {
            headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        if let Some(max_age) = &self.max_age {
            headers.insert(ACCESS_CONTROL_MAX_AGE, max_age.clone());
        }
        resp
    }

    /// Whether the preflight's `Access-Control-Request-Method` is allowed.
    fn preflight_method_allowed(&self, headers: &HeaderMap) -> bool {
        headers
            .get(ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|v| Method::from_bytes(v.as_bytes()).ok())
            .is_some_and(|m| self.allowed_methods.contains(&m))
    }

    /// Whether every header in `Access-Control-Request-Headers` is allowed.
    fn preflight_headers_allowed(&self, headers: &HeaderMap) -> bool {
        if self.allowed_headers_lower.is_empty() {
            return true;
        }
        let Some(requested) = headers.get(ACCESS_CONTROL_REQUEST_HEADERS) else {
            return true;
        };
        let Ok(requested) = requested.to_str() else {
            return false;
        };
        requested
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .all(|name| {
                self.allowed_headers_lower
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name))
            })
    }

    /// Adds CORS headers to an actual (non-preflight) response.
    fn decorate(&self, headers: &mut HeaderMap, origin: &HeaderValue) {
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, self.allow_origin_value(origin));
        if self.credentials {
            headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        if let Some(expose) = &self.expose_headers_value {
            headers.insert(ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
        }
    }
}

/// Tower layer applying one API's CORS policy.
#[derive(Debug, Clone)]
pub struct CorsLayer {
    state: Arc<CorsState>,
}

impl CorsLayer {
    /// Precompiles `config` into a layer; `api_id` names the API in errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when a method or header
    /// name does not compile. Definitions are validated before routes are
    /// built, so this failing indicates a validation gap, but the route
    /// build surfaces it loudly rather than panicking.
    pub fn from_config(config: &CorsConfig, api_id: &str) -> Result<Self, Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api_id.to_owned(),
            reason,
        };
        let wildcard = config.allowed_origins.iter().any(|o| o == "*");
        let allowed_methods = config
            .allowed_methods
            .iter()
            .map(|m| {
                Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                    .map_err(|_| fail(format!("invalid CORS method `{m}`")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let join = |names: &[String], what: &str| {
            HeaderValue::from_str(&names.join(", "))
                .map_err(|_| fail(format!("CORS {what} do not form a valid header value")))
        };
        let methods_joined = allowed_methods
            .iter()
            .map(Method::to_string)
            .collect::<Vec<_>>();
        Ok(Self {
            state: Arc::new(CorsState {
                wildcard,
                origins: config
                    .allowed_origins
                    .iter()
                    .filter(|o| *o != "*")
                    .map(|o| o.to_ascii_lowercase())
                    .collect(),
                allow_methods_value: join(&methods_joined, "allowed_methods")?,
                allowed_methods,
                allow_headers_value: if config.allowed_headers.is_empty() {
                    None
                } else {
                    Some(join(&config.allowed_headers, "allowed_headers")?)
                },
                allowed_headers_lower: config
                    .allowed_headers
                    .iter()
                    .map(|h| h.to_ascii_lowercase())
                    .collect(),
                expose_headers_value: if config.exposed_headers.is_empty() {
                    None
                } else {
                    Some(join(&config.exposed_headers, "exposed_headers")?)
                },
                credentials: config.allow_credentials,
                max_age: config
                    .max_age_secs
                    .map(|secs| HeaderValue::from_str(&secs.to_string()))
                    .transpose()
                    .map_err(|_| fail("CORS max_age_secs is not a valid header value".into()))?,
                options_passthrough: config.options_passthrough,
            }),
        })
    }
}

impl<S> Layer<S> for CorsLayer {
    type Service = Cors<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Cors {
            inner,
            state: Arc::clone(&self.state),
        }
    }
}

/// The [`Service`] produced by [`CorsLayer`].
#[derive(Debug, Clone)]
pub struct Cors<S> {
    inner: S,
    state: Arc<CorsState>,
}

impl<S> Service<Request<ProxyBody>> for Cors<S>
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
        // Same-origin (no Origin header): CORS does not apply.
        let Some(origin) = req.headers().get(ORIGIN).cloned() else {
            return Box::pin(self.inner.call(req));
        };

        let is_preflight = req.method() == Method::OPTIONS
            && req.headers().contains_key(ACCESS_CONTROL_REQUEST_METHOD);
        if is_preflight && !self.state.options_passthrough {
            let resp = self.state.preflight_response(&req, &origin);
            return Box::pin(std::future::ready(Ok(resp)));
        }

        let state = Arc::clone(&self.state);
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut resp = fut.await?;
            if state.origin_allowed(&origin) {
                state.decorate(resp.headers_mut(), &origin);
            }
            // The response differs by requesting origin whenever the policy
            // is origin-specific; caches must key on it either way.
            if !state.wildcard {
                resp.headers_mut()
                    .append(VARY, HeaderValue::from_static("origin"));
            }
            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::Full;
    use tower::ServiceExt;

    use super::*;

    fn body() -> ProxyBody {
        ProxyBody::new(Full::new(Bytes::new()))
    }

    /// Inner service marking that the request reached it.
    async fn upstream(_req: Request<ProxyBody>) -> Result<Response<ProxyBody>, Infallible> {
        let mut resp = Response::new(body());
        resp.headers_mut()
            .insert("x-upstream", HeaderValue::from_static("1"));
        Ok(resp)
    }

    fn layer(json: &str) -> CorsLayer {
        let config: CorsConfig = serde_json::from_str(json).expect("valid CORS JSON");
        config.validate("api").expect("valid config");
        CorsLayer::from_config(&config, "api").expect("compiles")
    }

    async fn send(layer: &CorsLayer, req: Request<ProxyBody>) -> Response<ProxyBody> {
        layer
            .layer(tower::service_fn(upstream))
            .oneshot(req)
            .await
            .expect("infallible")
    }

    fn preflight(origin: &str, method: &str, headers: Option<&str>) -> Request<ProxyBody> {
        let mut builder = Request::builder()
            .method(Method::OPTIONS)
            .uri("/x")
            .header(ORIGIN, origin)
            .header(ACCESS_CONTROL_REQUEST_METHOD, method);
        if let Some(headers) = headers {
            builder = builder.header(ACCESS_CONTROL_REQUEST_HEADERS, headers);
        }
        builder.body(body()).expect("request")
    }

    fn actual(origin: Option<&str>) -> Request<ProxyBody> {
        let mut builder = Request::builder().uri("/x");
        if let Some(origin) = origin {
            builder = builder.header(ORIGIN, origin);
        }
        builder.body(body()).expect("request")
    }

    fn header<'r>(resp: &'r Response<ProxyBody>, name: &str) -> Option<&'r str> {
        resp.headers().get(name).map(|v| v.to_str().expect("ascii"))
    }

    #[tokio::test]
    async fn same_origin_requests_pass_untouched() {
        let layer = layer(r#"{"allowed_origins": ["https://app.example.com"]}"#);
        let resp = send(&layer, actual(None)).await;
        assert!(resp.headers().contains_key("x-upstream"));
        assert!(header(&resp, "access-control-allow-origin").is_none());
        assert!(header(&resp, "vary").is_none());
    }

    #[tokio::test]
    async fn allowed_origin_is_echoed_with_vary() {
        let layer = layer(
            r#"{"allowed_origins": ["https://app.example.com"],
                "exposed_headers": ["X-Request-Id"],
                "allow_credentials": true}"#,
        );
        // Origin comparison is case-insensitive.
        let resp = send(&layer, actual(Some("https://APP.example.com"))).await;
        assert!(resp.headers().contains_key("x-upstream"));
        assert_eq!(
            header(&resp, "access-control-allow-origin"),
            Some("https://APP.example.com")
        );
        assert_eq!(
            header(&resp, "access-control-allow-credentials"),
            Some("true")
        );
        assert_eq!(
            header(&resp, "access-control-expose-headers"),
            Some("X-Request-Id")
        );
        assert_eq!(header(&resp, "vary"), Some("origin"));
    }

    #[tokio::test]
    async fn disallowed_origin_is_forwarded_without_cors_headers() {
        let layer = layer(r#"{"allowed_origins": ["https://app.example.com"]}"#);
        let resp = send(&layer, actual(Some("https://evil.example.com"))).await;
        // Not access control: the request still reaches the upstream.
        assert!(resp.headers().contains_key("x-upstream"));
        assert!(header(&resp, "access-control-allow-origin").is_none());
        assert_eq!(header(&resp, "vary"), Some("origin"));
    }

    #[tokio::test]
    async fn wildcard_origin_answers_star() {
        let layer = layer(r#"{"allowed_origins": ["*"]}"#);
        let resp = send(&layer, actual(Some("https://anyone.example"))).await;
        assert_eq!(header(&resp, "access-control-allow-origin"), Some("*"));
        assert!(header(&resp, "vary").is_none());
    }

    #[tokio::test]
    async fn preflight_is_answered_by_the_gateway() {
        let layer = layer(
            r#"{"allowed_origins": ["https://app.example.com"],
                "allowed_methods": ["GET", "DELETE"],
                "allowed_headers": ["Authorization", "Content-Type"],
                "max_age_secs": 600}"#,
        );
        let resp = send(
            &layer,
            preflight("https://app.example.com", "DELETE", Some("authorization")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        // Answered by the gateway, not the upstream.
        assert!(!resp.headers().contains_key("x-upstream"));
        assert_eq!(
            header(&resp, "access-control-allow-origin"),
            Some("https://app.example.com")
        );
        assert_eq!(
            header(&resp, "access-control-allow-methods"),
            Some("GET, DELETE")
        );
        assert_eq!(
            header(&resp, "access-control-allow-headers"),
            Some("Authorization, Content-Type")
        );
        assert_eq!(header(&resp, "access-control-max-age"), Some("600"));
        assert_eq!(
            header(&resp, "vary"),
            Some("origin, access-control-request-method, access-control-request-headers")
        );
    }

    #[tokio::test]
    async fn preflight_mirrors_requested_headers_when_none_configured() {
        let layer = layer(r#"{"allowed_origins": ["https://app.example.com"]}"#);
        let resp = send(
            &layer,
            preflight("https://app.example.com", "POST", Some("x-custom, x-other")),
        )
        .await;
        assert_eq!(
            header(&resp, "access-control-allow-headers"),
            Some("x-custom, x-other")
        );
    }

    #[tokio::test]
    async fn failing_preflights_get_no_allow_headers() {
        let layer = layer(
            r#"{"allowed_origins": ["https://app.example.com"],
                "allowed_methods": ["GET"],
                "allowed_headers": ["Content-Type"]}"#,
        );
        for (req, hint) in [
            (
                preflight("https://evil.example.com", "GET", None),
                "disallowed origin",
            ),
            (
                preflight("https://app.example.com", "DELETE", None),
                "disallowed method",
            ),
            (
                preflight("https://app.example.com", "GET", Some("x-secret")),
                "disallowed header",
            ),
        ] {
            let resp = send(&layer, req).await;
            assert_eq!(resp.status(), StatusCode::NO_CONTENT, "{hint}");
            assert!(
                header(&resp, "access-control-allow-origin").is_none(),
                "{hint}: must carry no allow headers"
            );
        }
    }

    #[tokio::test]
    async fn options_passthrough_forwards_preflights() {
        let layer = layer(
            r#"{"allowed_origins": ["https://app.example.com"], "options_passthrough": true}"#,
        );
        let resp = send(&layer, preflight("https://app.example.com", "GET", None)).await;
        // The upstream answered; the response is still decorated.
        assert!(resp.headers().contains_key("x-upstream"));
        assert_eq!(
            header(&resp, "access-control-allow-origin"),
            Some("https://app.example.com")
        );
    }

    #[tokio::test]
    async fn plain_options_without_request_method_is_not_a_preflight() {
        let layer = layer(r#"{"allowed_origins": ["https://app.example.com"]}"#);
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/x")
            .header(ORIGIN, "https://app.example.com")
            .body(body())
            .expect("request");
        let resp = send(&layer, req).await;
        assert!(resp.headers().contains_key("x-upstream"));
    }
}
