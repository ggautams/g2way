//! Dashboard-support endpoints: what a dashboard needs to render a node.
//!
//! - `GET /g2/node` — node identity, version, uptime, and the APIs the
//!   node is currently routing (from the live route table, so it reflects
//!   hot reloads immediately).
//! - `GET /g2/stats` — per-API request counters
//!   ([`g2_middleware::StatsRegistry`] snapshot): process-local and reset
//!   on restart. Cluster-wide durable analytics are milestone M5's
//!   `AnalyticsSink`.
//!
//! Both answer `503` when the router was built without a [`Dashboard`]
//! (possible for embedders; the g2way binary always wires one).

use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use g2_middleware::StatsRegistry;
use g2_proxy::Gateway;

use crate::{error_response, AdminState};

/// Live-gateway handles behind the dashboard endpoints.
///
/// Constructed by the binary after the [`Gateway`] exists and passed to
/// [`router`](crate::router).
#[derive(Clone)]
pub struct Dashboard {
    gateway: Arc<Gateway>,
    stats: Arc<StatsRegistry>,
    started_at: Instant,
}

impl Dashboard {
    /// Wires the dashboard to the running gateway and its stats registry.
    /// Uptime is measured from this call.
    #[must_use]
    pub fn new(gateway: Arc<Gateway>, stats: Arc<StatsRegistry>) -> Self {
        Self {
            gateway,
            stats,
            started_at: Instant::now(),
        }
    }
}

/// The 503 for a router built without a [`Dashboard`].
fn unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "node status unavailable on this deployment",
    )
}

/// `GET /g2/node` — node identity plus the APIs currently being routed.
#[utoipa::path(get, path = "/g2/node", tag = "dashboard",
    security(("admin_secret" = [])),
    responses(
        (status = 200, description = "Node identity, version, uptime, and the currently routed APIs"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Router built without dashboard wiring"),
    ))]
pub(crate) async fn node(State(state): State<AdminState>) -> Response {
    let Some(d) = &state.dashboard else {
        return unavailable();
    };
    let apis: Vec<serde_json::Value> = d
        .gateway
        .routes_snapshot()
        .iter()
        .map(|route| {
            serde_json::json!({
                "api_id": route.def.api_id,
                "name": route.def.name,
                "org_id": route.def.org_id,
                "listen_path": route.def.listen_path,
                "target_url": route.def.target_url,
                "target_list": route.def.target_list,
                // The addresses actually in rotation — equals the
                // configured targets until service discovery swaps them.
                // Versioned APIs show the unused base target (each version
                // rotates its own set, not surfaced here).
                "live_targets": route.target.live_targets(),
                // Per-address health flags (live_targets order); null when
                // health checking is off or the API is versioned (each
                // version probes its own target, not surfaced here).
                "target_health": route.target.target_health(),
                // Last discovery success/error; null when discovery is off
                // or the API is versioned (each version polls its own
                // endpoint, not surfaced here).
                "service_discovery": route.target.discovery_status().map(|s| {
                    serde_json::json!({
                        "endpoint": route.def.service_discovery.as_ref()
                            .map(|sd| sd.endpoint.clone()),
                        "last_success_unix_secs": s.last_success_unix_secs,
                        "last_error": s.last_error,
                    })
                }),
                // Last GraphQL schema-sync success/error; null when sync is
                // off or the API is versioned (each version syncs its own
                // schema, not surfaced here).
                "graphql_schema_sync": route.graphql_sync_status().map(|s| {
                    serde_json::json!({
                        "last_success_unix_secs": s.last_success_unix_secs,
                        "last_error": s.last_error,
                    })
                }),
                // Circuit state ("closed"/"open"/"half_open"); null when
                // breaking is off or the API is versioned (each version
                // keeps its own circuit, not surfaced here).
                "circuit_breaker": route.target.breaker_state(),
                "auth_mode": route.def.auth.mode_name(),
            })
        })
        .collect();
    Json(serde_json::json!({
        // The pod name under k8s; absent in bare processes.
        "node_id": std::env::var("HOSTNAME").ok(),
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": d.started_at.elapsed().as_secs(),
        "routes": apis.len(),
        "apis": apis,
    }))
    .into_response()
}

/// `GET /g2/stats` — per-API request counters since process start.
#[utoipa::path(get, path = "/g2/stats", tag = "dashboard",
    security(("admin_secret" = [])),
    responses(
        (status = 200, description = "Per-API request and status-class counters (process-local, reset on restart)"),
        (status = 403, description = "Admin secret missing or wrong"),
        (status = 503, description = "Router built without dashboard wiring"),
    ))]
pub(crate) async fn stats(State(state): State<AdminState>) -> Response {
    let Some(d) = &state.dashboard else {
        return unavailable();
    };
    Json(serde_json::json!({ "apis": d.stats.snapshot() })).into_response()
}
