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
//! - [`Error`] — the shared error type for configuration and validation
//!   failures.
//!
//! # Multi-organization readiness
//!
//! g2way currently runs single-organization, but every persistent record
//! carries an `org_id` (defaulting to [`DEFAULT_ORG_ID`]) so multi-org
//! support can be added later without a data migration.

pub mod api_definition;
pub mod config;
mod error;
pub mod loader;
pub mod session;

pub use api_definition::{ApiDefinition, AuthConfig, JwtSigningMethod, DEFAULT_ORG_ID};
pub use config::GatewayConfig;
pub use error::Error;
pub use session::KeySession;
