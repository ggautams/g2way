//! Storage-backed API definition loading.
//!
//! The second definition source next to the file loader
//! (`g2_core::loader::load_dir`), per ADR-0002: definitions created through
//! the admin API are persisted as JSON records under
//! `g2:{org_id}:apidef:{api_id}` and read back here at startup and on
//! reload. Both sources are merged by `g2_core::loader::merge_sources`.

use g2_core::api_definition::{api_definition_key_prefix, api_definition_storage_key};
use g2_core::ApiDefinition;

use crate::{Storage, StorageError};

/// Errors from [`load_api_definitions`].
#[derive(Debug, thiserror::Error)]
pub enum DefinitionLoadError {
    /// The backing store failed while scanning or reading records.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// A stored record is not a valid [`ApiDefinition`].
    ///
    /// A corrupt record fails the whole load rather than being skipped:
    /// skipping would silently unroute an API (ADR-0002).
    #[error("invalid API definition record at `{key}`: {reason}")]
    Record {
        /// Storage key of the offending record.
        key: String,
        /// What is wrong with it.
        reason: String,
    },
}

/// Loads every API definition stored under `org_id`, sorted by `api_id`.
///
/// Scans `g2:{org_id}:apidef:*`, parses each record as a JSON
/// [`ApiDefinition`], validates it, and requires it to live under exactly
/// the key its own `org_id`/`api_id` map to — a record that disagrees with
/// its key is corrupt. A key that disappears between the scan and the read
/// (deleted via the admin API) is skipped.
///
/// # Errors
///
/// Returns [`DefinitionLoadError::Storage`] when the store fails and
/// [`DefinitionLoadError::Record`] for an unparseable, invalid, or
/// misplaced record.
pub async fn load_api_definitions(
    storage: &dyn Storage,
    org_id: &str,
) -> Result<Vec<ApiDefinition>, DefinitionLoadError> {
    let record_err = |key: &str, reason: String| DefinitionLoadError::Record {
        key: key.to_owned(),
        reason,
    };

    let keys = storage
        .scan_prefix(&api_definition_key_prefix(org_id))
        .await?;
    let mut defs = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(raw) = storage.get(&key).await? else {
            tracing::debug!(%key, "definition deleted between scan and read; skipping");
            continue;
        };
        let def: ApiDefinition =
            serde_json::from_str(&raw).map_err(|e| record_err(&key, e.to_string()))?;
        def.validate()
            .map_err(|e| record_err(&key, e.to_string()))?;
        if api_definition_storage_key(&def.org_id, &def.api_id) != key {
            return Err(record_err(
                &key,
                format!(
                    "record's org_id `{}` / api_id `{}` do not match its storage key",
                    def.org_id, def.api_id
                ),
            ));
        }
        tracing::debug!(api_id = %def.api_id, %key, "loaded API definition from storage");
        defs.push(def);
    }
    defs.sort_by(|a, b| a.api_id.cmp(&b.api_id));
    Ok(defs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStorage;
    use g2_core::DEFAULT_ORG_ID;

    fn def_json(api_id: &str, listen_path: &str) -> String {
        format!(
            r#"{{"api_id":"{api_id}","name":"{api_id}","listen_path":"{listen_path}","target_url":"http://up.internal"}}"#
        )
    }

    async fn seed(store: &MemoryStorage, org: &str, api_id: &str, listen_path: &str) {
        store
            .set(
                &api_definition_storage_key(org, api_id),
                &def_json(api_id, listen_path),
                None,
            )
            .await
            .expect("seed");
    }

    #[tokio::test]
    async fn loads_org_definitions_sorted_by_api_id() {
        let store = MemoryStorage::new();
        seed(&store, DEFAULT_ORG_ID, "beta", "/beta/").await;
        seed(&store, DEFAULT_ORG_ID, "alpha", "/alpha/").await;
        seed(&store, "other-org", "gamma", "/gamma/").await;
        // Unrelated kinds under the same org must not be picked up.
        store
            .set("g2:default:apikey:abc123", "{}", None)
            .await
            .expect("seed key");

        let defs = load_api_definitions(&store, DEFAULT_ORG_ID)
            .await
            .expect("load");
        let ids: Vec<_> = defs.iter().map(|d| d.api_id.as_str()).collect();
        assert_eq!(ids, ["alpha", "beta"]);
    }

    #[tokio::test]
    async fn empty_storage_loads_zero_definitions() {
        let store = MemoryStorage::new();
        assert!(load_api_definitions(&store, DEFAULT_ORG_ID)
            .await
            .expect("load")
            .is_empty());
    }

    #[tokio::test]
    async fn unparseable_record_fails_the_load_naming_its_key() {
        let store = MemoryStorage::new();
        let key = api_definition_storage_key(DEFAULT_ORG_ID, "bad");
        store.set(&key, "{ nope", None).await.expect("seed");

        let err = load_api_definitions(&store, DEFAULT_ORG_ID)
            .await
            .expect_err("corrupt record");
        assert!(matches!(err, DefinitionLoadError::Record { .. }));
        assert!(err.to_string().contains(&key), "got: {err}");
    }

    #[tokio::test]
    async fn invalid_definition_fails_the_load() {
        let store = MemoryStorage::new();
        seed(&store, DEFAULT_ORG_ID, "bad", "no-leading-slash").await;

        let err = load_api_definitions(&store, DEFAULT_ORG_ID)
            .await
            .expect_err("invalid record");
        assert!(err.to_string().contains("listen_path"), "got: {err}");
    }

    #[tokio::test]
    async fn record_disagreeing_with_its_key_fails_the_load() {
        let store = MemoryStorage::new();
        // Valid definition, stored under a key claiming a different api_id.
        store
            .set(
                &api_definition_storage_key(DEFAULT_ORG_ID, "claimed"),
                &def_json("actual", "/actual/"),
                None,
            )
            .await
            .expect("seed");

        let err = load_api_definitions(&store, DEFAULT_ORG_ID)
            .await
            .expect_err("misplaced record");
        assert!(err.to_string().contains("do not match"), "got: {err}");
    }
}
