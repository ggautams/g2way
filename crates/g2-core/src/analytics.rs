//! Per-request analytics records (traffic analytics).
//!
//! An [`AnalyticsRecord`] is the durable, per-request counterpart to the
//! process-local dashboard counters: one record per proxied request,
//! carrying what a traffic dashboard or billing pipeline needs (identity,
//! outcome, latency). Records are produced by `g2-middleware`'s analytics
//! layer and delivered by an `AnalyticsSink` implementation in
//! `g2-telemetry`; this crate only defines the shared shape.

use serde::{Deserialize, Serialize};

/// Storage key of the org's analytics record list (the Redis-list sink's
/// destination, and where a future analytics pump reads from):
/// `g2:{org_id}:analytics:records`.
#[must_use]
pub fn analytics_records_key(org_id: &str) -> String {
    format!("g2:{org_id}:analytics:records")
}

/// One proxied request, as seen by the analytics pipeline.
///
/// Serialized to JSON by every sink, so the field names are the wire
/// format. Optional fields are omitted when absent (`None`) and tolerate
/// absence when deserializing, keeping old records readable as the schema
/// grows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyticsRecord {
    /// When the request arrived at the gateway (Unix epoch, milliseconds).
    pub timestamp_unix_ms: u64,

    /// The `api_id` of the matched API definition.
    pub api_id: String,

    /// The organization owning the matched API.
    pub org_id: String,

    /// HTTP request method.
    pub method: String,

    /// Request path as received from the client (no query string — it can
    /// carry credentials).
    pub path: String,

    /// HTTP response status sent to the client.
    pub status: u16,

    /// Total time to answer the client, gateway overhead included
    /// (milliseconds).
    pub latency_ms: u64,

    /// Time spent on the upstream round trip, when the request reached the
    /// forwarder (milliseconds). Absent for requests rejected inside the
    /// gateway (auth failures, rate limits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_latency_ms: Option<u64>,

    /// SHA-256 hex digest identifying the authenticated key (never the raw
    /// credential). Absent for keyless APIs and rejected requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_hash: Option<String>,

    /// Human-readable alias of the authenticated key's session, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_alias: Option<String>,

    /// The client's remote IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,

    /// The request's `User-Agent` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// The request's `Content-Length` header, when present and numeric.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_content_length: Option<u64>,

    /// The response's `Content-Length` header, when present and numeric.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content_length: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> AnalyticsRecord {
        AnalyticsRecord {
            timestamp_unix_ms: 1_756_600_000_000,
            api_id: "users-api".into(),
            org_id: "default".into(),
            method: "GET".into(),
            path: "/users/42".into(),
            status: 200,
            latency_ms: 12,
            upstream_latency_ms: Some(9),
            key_hash: Some("ab34".into()),
            key_alias: Some("mobile-app".into()),
            client_ip: Some("10.0.0.9".into()),
            user_agent: Some("curl/8".into()),
            request_content_length: None,
            response_content_length: Some(128),
        }
    }

    #[test]
    fn storage_key_follows_schema() {
        assert_eq!(analytics_records_key("acme"), "g2:acme:analytics:records");
    }

    #[test]
    fn serializes_round_trip_and_omits_absent_fields() {
        let json = serde_json::to_string(&record()).expect("serialize");
        assert!(json.contains("\"api_id\":\"users-api\""), "{json}");
        assert!(
            !json.contains("request_content_length"),
            "absent optionals must be omitted: {json}"
        );
        let back: AnalyticsRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, record());
    }

    #[test]
    fn deserializes_records_missing_optional_fields() {
        // A minimal record, as an older gateway (or leaner schema) would
        // have written it.
        let back: AnalyticsRecord = serde_json::from_str(
            r#"{"timestamp_unix_ms":1,"api_id":"a","org_id":"o","method":"GET",
                "path":"/","status":200,"latency_ms":3}"#,
        )
        .expect("deserialize");
        assert_eq!(back.upstream_latency_ms, None);
        assert_eq!(back.key_hash, None);
    }
}
