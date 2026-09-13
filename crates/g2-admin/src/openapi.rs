//! The admin API's OpenAPI document, served at `GET /g2/openapi.json`.
//!
//! Assembled by utoipa from the `#[utoipa::path]` annotations colocated
//! with every handler (and the concrete bindings in [`crate::resources`])
//! plus the `ToSchema` derives on the g2-core models (the crate's
//! `openapi` feature). A dashboard or client generator reads one URL and
//! gets the whole admin surface.

use axum::response::{IntoResponse, Response};
use axum::Json;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

/// Registers the `admin_secret` security scheme: the
/// [`ADMIN_AUTH_HEADER`](crate::ADMIN_AUTH_HEADER) API-key header every
/// authenticated operation demands.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_default();
        components.add_security_scheme(
            "admin_secret",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-G2-Authorization",
                "The gateway's configured admin secret",
            ))),
        );
    }
}

/// The assembled OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "g2way admin API",
        description = "Control-plane API of the g2way gateway: key, API \
                       definition, and policy management, hot reload, and \
                       node status. Definition/policy writes go live on \
                       reload, not on write."
    ),
    paths(
        crate::health,
        crate::prometheus_metrics,
        crate::version,
        crate::reload,
        crate::dashboard::node,
        crate::dashboard::stats,
        crate::keys::list_keys,
        crate::keys::create_key,
        crate::keys::get_key,
        crate::keys::put_key,
        crate::keys::delete_key,
        crate::resources::list_apis,
        crate::resources::create_api,
        crate::resources::get_api,
        crate::resources::put_api,
        crate::resources::delete_api,
        crate::resources::list_policies,
        crate::resources::create_policy,
        crate::resources::get_policy,
        crate::resources::put_policy,
        crate::resources::delete_policy,
    ),
    components(schemas(
        g2_core::ApiDefinition,
        g2_core::AuthConfig,
        g2_core::JwtSigningMethod,
        g2_core::HeaderTransforms,
        g2_core::HeaderTransform,
        g2_core::UrlRewriteRule,
        g2_core::PathRule,
        g2_core::MockResponse,
        g2_core::CorsConfig,
        g2_core::HealthCheckConfig,
        g2_core::CircuitBreakerConfig,
        g2_core::VersioningConfig,
        g2_core::VersionOverrides,
        g2_core::VersionLocation,
        g2_core::KeySession,
        g2_core::Policy,
        g2_core::session::RateLimit,
        g2_core::session::Quota,
        g2_core::session::ApiAccess,
        g2_core::session::BasicAuthData,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "system", description = "Health, version, hot reload"),
        (name = "keys", description = "API key sessions (stored hashed)"),
        (name = "apis", description = "API definitions (storage source; live on reload)"),
        (name = "policies", description = "Reusable rate/quota/ACL bundles"),
        (name = "dashboard", description = "Node status and per-API stats"),
    )
)]
struct ApiDoc;

/// `GET /g2/openapi.json` — the document itself (authenticated, like the
/// rest of the admin surface).
pub(crate) async fn spec() -> Response {
    Json(ApiDoc::openapi()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_documents_every_mounted_route() {
        let doc = ApiDoc::openapi();
        // Every path the router mounts (except this spec route itself)
        // must be documented; a new route without an annotation fails here.
        for path in [
            "/g2/health",
            "/metrics",
            "/g2/version",
            "/g2/reload",
            "/g2/node",
            "/g2/stats",
            "/g2/keys",
            "/g2/keys/{key}",
            "/g2/apis",
            "/g2/apis/{id}",
            "/g2/policies",
            "/g2/policies/{id}",
        ] {
            assert!(
                doc.paths.paths.contains_key(path),
                "path `{path}` missing from the OpenAPI document"
            );
        }
        let schemas = &doc.components.as_ref().expect("components").schemas;
        for schema in [
            "ApiDefinition",
            "KeySession",
            "Policy",
            "PathRule",
            "MockResponse",
            "CorsConfig",
            "HealthCheckConfig",
            "CircuitBreakerConfig",
            "VersioningConfig",
            "VersionOverrides",
        ] {
            assert!(schemas.contains_key(schema), "schema `{schema}` missing");
        }
    }

    #[test]
    fn spec_serializes_to_json() {
        let json = serde_json::to_string(&ApiDoc::openapi()).expect("serializes");
        assert!(json.contains("\"openapi\""), "not an OpenAPI document");
        assert!(
            json.contains("X-G2-Authorization"),
            "security scheme missing"
        );
    }
}
