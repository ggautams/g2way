//! The [`KeySession`] model: the state attached to one API key.
//!
//! A session is what an auth middleware resolves a credential into: which
//! organization the key belongs to, which APIs it may call, how fast and how
//! much it may call them, and when it stops working. It is the gateway's
//! single unit of per-credential state.
//!
//! # Key hashing
//!
//! Raw API keys are never persisted. Storage and admin operations address a
//! session by the lowercase-hex SHA-256 of the raw key ([`hash_key`]), stored
//! under `g2:{org_id}:apikey:{key_hash}` ([`session_storage_key`]). A leaked
//! storage dump therefore reveals no usable credentials.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api_definition::DEFAULT_ORG_ID;
use crate::Error;

fn default_org_id() -> String {
    DEFAULT_ORG_ID.to_owned()
}

fn default_true() -> bool {
    true
}

/// A request-rate allowance: at most `requests` per `per_seconds` window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum number of requests allowed inside one window.
    pub requests: u64,

    /// Length of the sliding window in seconds.
    pub per_seconds: u64,
}

/// A long-period usage quota: at most `max` requests per renewal period.
///
/// Unlike [`RateLimit`] (a smoothing limit over seconds or minutes), a quota
/// is a billing-style allowance over hours or days. The live counter and its
/// reset timestamp are kept in storage (milestone M3), not on the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// Maximum number of requests allowed inside one renewal period.
    pub max: u64,

    /// Length of the renewal period in seconds (for example `3600` for an
    /// hourly quota).
    pub renewal_rate_secs: u64,
}

/// Basic-auth credential data attached to a session.
///
/// Present only on sessions addressed by a username (basic-auth mode); the
/// presented password is verified against `password_hash` on every request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicAuthData {
    /// bcrypt hash of the user's password (a full `$2b$…` hash string).
    /// The plaintext password is never persisted.
    pub password_hash: String,
}

/// Access granted to a single API.
///
/// Today an entry's presence in [`KeySession::access`] is the whole grant;
/// per-API rate/quota overrides arrive with policies (milestone M4), which is
/// why this is a struct rather than a bare set membership.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiAccess {}

/// The state attached to one API key.
///
/// Sessions are created through the admin API (or seeded directly in
/// storage), persisted as JSON under [`session_storage_key`], and looked up
/// by auth middleware on every request carrying the key.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "alias": "acme-mobile-app",
///   "rate": { "requests": 100, "per_seconds": 60 },
///   "quota": { "max": 10000, "renewal_rate_secs": 3600 },
///   "expires_at": 1790000000,
///   "access": { "httpbin": {} }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySession {
    /// Owning organization. Always [`DEFAULT_ORG_ID`] in single-org mode.
    #[serde(default = "default_org_id")]
    pub org_id: String,

    /// Optional human-readable label, shown in logs and analytics in place
    /// of the (hashed, unreadable) key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,

    /// Request-rate allowance. `None` means unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<RateLimit>,

    /// Long-period usage quota. `None` means unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quota>,

    /// Unix timestamp (seconds) after which the key stops working.
    /// `None` means the key never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Inactive sessions fail auth without being deleted (a soft revoke).
    #[serde(default = "default_true")]
    pub active: bool,

    /// APIs this key may call, keyed by `api_id`. An **empty map grants
    /// access to every API in the organization** (the behavior for keys
    /// without access rights).
    #[serde(default)]
    pub access: BTreeMap<String, ApiAccess>,

    /// Basic-auth credentials, set only on sessions used with the
    /// basic-auth mode. `None` means this session cannot authenticate via
    /// basic auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuthData>,
}

impl Default for KeySession {
    /// An active, never-expiring session in the default org with no rate,
    /// quota, or access restrictions.
    fn default() -> Self {
        Self {
            org_id: default_org_id(),
            alias: None,
            rate: None,
            quota: None,
            expires_at: None,
            active: true,
            access: BTreeMap::new(),
            basic_auth: None,
        }
    }
}

impl KeySession {
    /// Validates the semantic invariants that serde cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeySession`] when `org_id` is empty or a
    /// rate/quota field is zero (use `None` for "unlimited", never zero).
    pub fn validate(&self) -> Result<(), Error> {
        let fail = |reason: &str| Error::InvalidKeySession {
            reason: reason.to_owned(),
        };

        if self.org_id.trim().is_empty() {
            return Err(fail("`org_id` must not be empty"));
        }
        if let Some(rate) = &self.rate {
            if rate.requests == 0 {
                return Err(fail("`rate.requests` must be greater than zero"));
            }
            if rate.per_seconds == 0 {
                return Err(fail("`rate.per_seconds` must be greater than zero"));
            }
        }
        if let Some(quota) = &self.quota {
            if quota.max == 0 {
                return Err(fail("`quota.max` must be greater than zero"));
            }
            if quota.renewal_rate_secs == 0 {
                return Err(fail("`quota.renewal_rate_secs` must be greater than zero"));
            }
        }
        for api_id in self.access.keys() {
            if api_id.trim().is_empty() {
                return Err(fail("`access` keys (api_id) must not be empty"));
            }
        }
        if let Some(basic) = &self.basic_auth {
            if basic.password_hash.trim().is_empty() {
                return Err(fail("`basic_auth.password_hash` must not be empty"));
            }
        }
        Ok(())
    }

    /// Whether the session has expired as of `now_unix_secs`.
    ///
    /// A session with no `expires_at` never expires. Takes the clock as an
    /// argument so callers read the clock once per request and tests need no
    /// real time.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        match self.expires_at {
            Some(expires_at) => now_unix_secs >= expires_at,
            None => false,
        }
    }

    /// Whether this session grants access to `api_id`.
    ///
    /// An empty access map grants access to every API in the organization.
    #[must_use]
    pub fn allows_api(&self, api_id: &str) -> bool {
        self.access.is_empty() || self.access.contains_key(api_id)
    }
}

/// Hashes a raw API key to the lowercase-hex SHA-256 digest used as its
/// storage identity.
///
/// The raw key is never persisted; every lookup hashes the presented
/// credential and fetches the session stored under the digest.
#[must_use]
pub fn hash_key(raw_key: &str) -> String {
    hex::encode(Sha256::digest(raw_key.as_bytes()))
}

/// Builds the storage key for a session: `g2:{org_id}:apikey:{key_hash}`.
///
/// `key_hash` is the output of [`hash_key`], not the raw credential.
#[must_use]
pub fn session_storage_key(org_id: &str, key_hash: &str) -> String {
    format!("g2:{org_id}:apikey:{key_hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_session_is_unrestricted_and_valid() {
        let session = KeySession::default();
        assert_eq!(session.org_id, DEFAULT_ORG_ID);
        assert!(session.active);
        assert!(!session.is_expired(u64::MAX));
        assert!(session.allows_api("anything"));
        session.validate().expect("default session is valid");
    }

    #[test]
    fn minimal_json_gets_defaults() {
        let session: KeySession = serde_json::from_str("{}").expect("empty object parses");
        assert_eq!(session, KeySession::default());
    }

    #[test]
    fn full_json_round_trips() {
        let session = KeySession {
            org_id: "acme".into(),
            alias: Some("acme-mobile-app".into()),
            rate: Some(RateLimit {
                requests: 100,
                per_seconds: 60,
            }),
            quota: Some(Quota {
                max: 10_000,
                renewal_rate_secs: 3_600,
            }),
            expires_at: Some(1_790_000_000),
            active: true,
            access: BTreeMap::from([("httpbin".to_owned(), ApiAccess::default())]),
            basic_auth: Some(BasicAuthData {
                password_hash: "$2b$12$abcdefghijklmnopqrstuv".into(),
            }),
        };
        session.validate().expect("full session is valid");
        let json = serde_json::to_string(&session).expect("serializes");
        let back: KeySession = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, session);
    }

    #[test]
    fn unlimited_fields_are_omitted_from_json() {
        let json = serde_json::to_string(&KeySession::default()).expect("serializes");
        for absent in ["alias", "rate", "quota", "expires_at", "basic_auth"] {
            assert!(
                !json.contains(absent),
                "`{absent}` should be omitted: {json}"
            );
        }
    }

    #[test]
    fn zero_rate_and_quota_fields_are_rejected() {
        let cases: [(&str, KeySession); 4] = [
            (
                "rate.requests",
                KeySession {
                    rate: Some(RateLimit {
                        requests: 0,
                        per_seconds: 60,
                    }),
                    ..KeySession::default()
                },
            ),
            (
                "rate.per_seconds",
                KeySession {
                    rate: Some(RateLimit {
                        requests: 10,
                        per_seconds: 0,
                    }),
                    ..KeySession::default()
                },
            ),
            (
                "quota.max",
                KeySession {
                    quota: Some(Quota {
                        max: 0,
                        renewal_rate_secs: 3_600,
                    }),
                    ..KeySession::default()
                },
            ),
            (
                "quota.renewal_rate_secs",
                KeySession {
                    quota: Some(Quota {
                        max: 100,
                        renewal_rate_secs: 0,
                    }),
                    ..KeySession::default()
                },
            ),
        ];
        for (field, session) in cases {
            let err = session.validate().unwrap_err();
            assert!(err.to_string().contains(field), "`{field}`: got {err}");
        }
    }

    #[test]
    fn empty_org_id_and_access_key_are_rejected() {
        let session = KeySession {
            org_id: "  ".into(),
            ..KeySession::default()
        };
        assert!(session.validate().is_err());

        let session = KeySession {
            access: BTreeMap::from([(String::new(), ApiAccess::default())]),
            ..KeySession::default()
        };
        assert!(session.validate().is_err());
    }

    #[test]
    fn empty_basic_auth_password_hash_is_rejected() {
        let session = KeySession {
            basic_auth: Some(BasicAuthData {
                password_hash: "  ".into(),
            }),
            ..KeySession::default()
        };
        let err = session.validate().unwrap_err();
        assert!(err.to_string().contains("password_hash"), "got: {err}");
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let session = KeySession {
            expires_at: Some(1_000),
            ..KeySession::default()
        };
        assert!(!session.is_expired(999));
        assert!(
            session.is_expired(1_000),
            "expires exactly at the timestamp"
        );
        assert!(session.is_expired(1_001));
    }

    #[test]
    fn access_map_restricts_apis_when_non_empty() {
        let session = KeySession {
            access: BTreeMap::from([("users".to_owned(), ApiAccess::default())]),
            ..KeySession::default()
        };
        assert!(session.allows_api("users"));
        assert!(!session.allows_api("orders"));
    }

    #[test]
    fn hash_key_matches_known_sha256_vector() {
        // SHA-256("abc") — FIPS 180-2 test vector.
        assert_eq!(
            hash_key("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(hash_key("abc"), hash_key("abd"));
    }

    #[test]
    fn storage_key_follows_schema() {
        let hash = hash_key("my-secret-key");
        assert_eq!(
            session_storage_key("default", &hash),
            format!("g2:default:apikey:{hash}")
        );
    }
}
