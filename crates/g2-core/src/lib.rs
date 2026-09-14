//! Core domain types for the g2way API gateway.
//!
//! This crate holds the vocabulary shared by every other g2way crate:
//!
//! - [`ApiDefinition`] — the unit of gateway configuration: one upstream API
//!   exposed on a listen path.
//! - [`GatewayConfig`] — process-level gateway settings (listen address,
//!   where API definitions are loaded from, and so on).
//! - [`KeySession`] — the state attached to one API key: org, per-API
//!   access, rate/quota allowances, expiry (keys are stored hashed; see
//!   [`session::hash_key`]).
//! - [`Policy`] — a reusable rate/quota/ACL bundle; keys referencing one
//!   inherit its allowances instead of carrying their own.
//! - [`Error`] — the shared error type for configuration and validation
//!   failures.
//!
//! # Multi-organization readiness
//!
//! g2way currently runs single-organization, but every persistent record
//! carries an `org_id` (defaulting to [`DEFAULT_ORG_ID`]) so multi-org
//! support can be added later without a data migration.

pub mod analytics;
pub mod api_definition;
pub mod body_transform;
pub mod config;
pub mod endpoints;
mod error;
pub mod graphql;
pub mod loader;
pub mod plugins;
pub mod policy;
pub mod security;
pub mod session;
pub mod transform;
pub mod versioning;

pub use analytics::AnalyticsRecord;
pub use api_definition::{
    ApiDefinition, AuthConfig, CacheConfig, CircuitBreakerConfig, DiscoveredEntry,
    HealthCheckConfig, HmacAlgorithm, JwtSigningMethod, ServiceDiscoveryConfig, DEFAULT_ORG_ID,
};
pub use body_transform::{BodyTransformRule, BodyTransforms};
pub use config::{AnalyticsSinkKind, ClientCertMode, GatewayConfig, SpikeGuardConfig, TlsConfig};
pub use endpoints::{EndpointRateLimit, MockResponse, PathRule};
pub use error::Error;
pub use graphql::{GraphQlConfig, GraphQlExecutionMode, PersistedQuery, PlaygroundConfig};
pub use plugins::{PluginRef, PluginsConfig};
pub use policy::Policy;
pub use security::CorsConfig;
pub use session::{BasicAuthData, HmacData, KeySession};
pub use transform::{HeaderTransform, HeaderTransforms, UrlRewriteRule};
pub use versioning::{VersionLocation, VersionOverrides, VersioningConfig};
