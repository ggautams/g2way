//! The [`Policy`] model: a reusable rate/quota/ACL bundle applied to keys.
//!
//! A policy is the answer to per-key configuration sprawl: instead of
//! every key carrying its own rate, quota, and API access list, keys
//! reference a policy ([`KeySession::apply_policies`]) and inherit its
//! allowances. Editing the policy retunes every key that references it.
//!
//! Policies are persisted as JSON under `g2:{org_id}:policy:{policy_id}`
//! ([`policy_storage_key`], ADR-0002) and resolved by the auth middleware
//! when a stored session referencing one is loaded.
//!
//! [`KeySession::apply_policies`]: crate::KeySession::apply_policies

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::api_definition::DEFAULT_ORG_ID;
use crate::session::{ApiAccess, Quota, RateLimit};
use crate::Error;

fn default_org_id() -> String {
    DEFAULT_ORG_ID.to_owned()
}

fn default_true() -> bool {
    true
}

/// A reusable bundle of rate, quota, and API access settings.
///
/// When a key references a policy, the policy's `rate`, `quota`, and
/// `access` **replace** the session's own wholesale (non-partitioned
/// policy semantics; partitioned policies, which override selectively, are
/// a possible later refinement). Per-key state — expiry, active flag,
/// alias, basic-auth credentials — is never touched by a policy.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "policy_id": "free-tier",
///   "name": "Free tier",
///   "rate": { "requests": 10, "per_seconds": 60 },
///   "quota": { "max": 1000, "renewal_rate_secs": 86400 },
///   "access": { "httpbin": {} }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Unique, stable identifier keys reference in `apply_policies`.
    pub policy_id: String,

    /// Human-readable name (shown in logs and the future dashboard).
    pub name: String,

    /// Owning organization. Always [`DEFAULT_ORG_ID`] in single-org mode.
    #[serde(default = "default_org_id")]
    pub org_id: String,

    /// An inactive policy denies every key that references it (a soft kill
    /// switch for a whole tier of keys).
    #[serde(default = "default_true")]
    pub active: bool,

    /// Request-rate allowance granted to referencing keys. `None` means
    /// unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<RateLimit>,

    /// Long-period usage quota granted to referencing keys. `None` means
    /// unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quota>,

    /// APIs referencing keys may call, keyed by `api_id`. An **empty map
    /// grants access to every API in the organization** (same rule as
    /// [`KeySession::access`](crate::KeySession::access)).
    #[serde(default)]
    pub access: BTreeMap<String, ApiAccess>,
}

impl Policy {
    /// Validates the semantic invariants that serde cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPolicy`] when `policy_id`, `name`, or
    /// `org_id` is empty, a rate/quota field is zero (use `None` for
    /// "unlimited", never zero), or an `access` key is empty.
    pub fn validate(&self) -> Result<(), Error> {
        let fail = |reason: &str| Error::InvalidPolicy {
            policy: self.policy_id.clone(),
            reason: reason.to_owned(),
        };

        if self.policy_id.trim().is_empty() {
            return Err(fail("`policy_id` must not be empty"));
        }
        if self.name.trim().is_empty() {
            return Err(fail("`name` must not be empty"));
        }
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
        Ok(())
    }
}

/// Storage key holding one policy: `g2:{org_id}:policy:{policy_id}`.
#[must_use]
pub fn policy_storage_key(org_id: &str, policy_id: &str) -> String {
    format!("{}{policy_id}", policy_key_prefix(org_id))
}

/// Prefix shared by every policy key in `org_id`: `g2:{org_id}:policy:`.
#[must_use]
pub fn policy_key_prefix(org_id: &str) -> String {
    format!("g2:{org_id}:policy:")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_json() -> &'static str {
        r#"{ "policy_id": "free-tier", "name": "Free tier" }"#
    }

    fn parse(json: &str) -> Policy {
        serde_json::from_str(json).expect("valid policy JSON")
    }

    #[test]
    fn minimal_policy_gets_defaults_and_validates() {
        let policy = parse(minimal_json());
        assert_eq!(policy.org_id, DEFAULT_ORG_ID);
        assert!(policy.active);
        assert!(policy.rate.is_none() && policy.quota.is_none());
        assert!(policy.access.is_empty());
        policy.validate().expect("minimal policy is valid");
    }

    #[test]
    fn empty_identity_fields_are_rejected() {
        for field in ["policy_id", "name", "org_id"] {
            let mut policy = parse(minimal_json());
            match field {
                "policy_id" => policy.policy_id = "  ".into(),
                "name" => policy.name = String::new(),
                _ => policy.org_id = String::new(),
            }
            assert!(
                policy.validate().is_err(),
                "expected empty `{field}` rejected"
            );
        }
    }

    #[test]
    fn zero_rate_and_quota_fields_are_rejected() {
        let mut policy = parse(minimal_json());
        policy.rate = Some(RateLimit {
            requests: 0,
            per_seconds: 60,
        });
        assert!(policy.validate().is_err());

        let mut policy = parse(minimal_json());
        policy.quota = Some(Quota {
            max: 100,
            renewal_rate_secs: 0,
        });
        assert!(policy.validate().is_err());
    }

    #[test]
    fn empty_access_api_id_is_rejected() {
        let mut policy = parse(minimal_json());
        policy.access.insert(String::new(), ApiAccess::default());
        assert!(policy.validate().is_err());
    }

    #[test]
    fn storage_key_follows_schema() {
        assert_eq!(
            policy_storage_key("default", "free-tier"),
            "g2:default:policy:free-tier"
        );
        assert_eq!(policy_key_prefix("default"), "g2:default:policy:");
    }

    #[test]
    fn full_policy_round_trips_through_json() {
        let policy = Policy {
            policy_id: "gold".into(),
            name: "Gold tier".into(),
            org_id: DEFAULT_ORG_ID.into(),
            active: true,
            rate: Some(RateLimit {
                requests: 100,
                per_seconds: 60,
            }),
            quota: Some(Quota {
                max: 10_000,
                renewal_rate_secs: 86_400,
            }),
            access: [("httpbin".to_owned(), ApiAccess::default())].into(),
        };
        policy.validate().expect("valid");
        let json = serde_json::to_string(&policy).expect("serializes");
        assert_eq!(parse(&json), policy);
    }
}
