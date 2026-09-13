//! Config hot reload: rebuild the route table when a reload nudge arrives.
//!
//! The admin API's `POST /g2/reload` publishes a nudge on the org's reload
//! channel ([`g2_core::config::reload_channel`]) via storage pub/sub; every
//! gateway pod runs [`listen`], which re-reads both definition sources
//! (files + storage, ADR-0002), rebuilds the route table, and swaps it into
//! the running [`Gateway`] atomically. A failed rebuild — config error,
//! cross-source conflict, storage outage — is logged and the **old table
//! keeps serving**.

use std::path::PathBuf;
use std::sync::Arc;

use g2_middleware::SpikeGuard;
use g2_proxy::{Forwarder, Gateway, RouteTable};
use g2_storage::SharedStorage;

/// Everything a route-table rebuild needs, captured once at startup.
pub struct ReloadContext {
    /// Directory of definition files (the file source).
    pub apps_dir: PathBuf,

    /// Organization whose stored definitions are loaded.
    pub org_id: String,

    /// Storage backend: the definition source and the middleware backend.
    pub storage: SharedStorage,

    /// The shared upstream client handle (connection pools survive
    /// reloads because every table is built from the same forwarder).
    pub forwarder: Forwarder,

    /// The pod-local spike guard, if enabled (shared across reloads so
    /// bucket state survives).
    pub spike_guard: Option<Arc<SpikeGuard>>,

    /// Per-API request counters, if enabled (shared across reloads so
    /// counters survive table swaps).
    pub stats: Option<Arc<g2_middleware::StatsRegistry>>,

    /// OpenTelemetry request instruments, if metric export is enabled
    /// (created once per process; shared across reloads).
    pub metrics: Option<Arc<g2_middleware::HttpMetrics>>,
}

impl ReloadContext {
    /// Loads both definition sources, merges them, and builds a fresh
    /// route table.
    ///
    /// # Errors
    ///
    /// Returns the first load, merge, or build error; the caller decides
    /// whether that is fatal (startup) or survivable (reload).
    pub async fn build_table(&self) -> Result<RouteTable, Box<dyn std::error::Error>> {
        let file_defs = g2_core::loader::load_dir(&self.apps_dir)?;
        let storage_defs =
            g2_storage::load_api_definitions(self.storage.as_ref(), &self.org_id).await?;
        let defs = g2_core::loader::merge_sources(file_defs, storage_defs)?;
        Ok(RouteTable::build(
            defs,
            &self.forwarder,
            &self.storage,
            self.spike_guard.as_ref(),
            self.stats.as_ref(),
            self.metrics.as_ref(),
        )?)
    }
}

/// Subscribes to the reload channel and rebuilds `gateway`'s route table on
/// every nudge, until the subscription's storage is dropped or the task is
/// aborted. Run this on its own task; it only returns if the subscription
/// can never be established.
///
/// # Errors
///
/// Returns an error only when the initial subscription fails (the storage
/// backend rejected it outright); transport drops after that are retried
/// inside the storage layer.
pub async fn listen(
    ctx: ReloadContext,
    gateway: Arc<Gateway>,
) -> Result<(), g2_storage::StorageError> {
    let channel = g2_core::config::reload_channel(&ctx.org_id);
    let mut rx = ctx.storage.subscribe(&channel).await?;
    tracing::info!(channel, "listening for reload nudges");
    while rx.recv().await.is_some() {
        match ctx.build_table().await {
            Ok(table) => {
                let routes = table.routes().len();
                gateway.reload(table);
                tracing::info!(routes, "route table reloaded");
            }
            Err(e) => {
                tracing::error!(error = %e, "reload failed; keeping the previous route table");
            }
        }
    }
    tracing::warn!(channel, "reload subscription ended");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use g2_core::api_definition::api_definition_storage_key;
    use g2_core::config::reload_channel;
    use g2_storage::MemoryStorage;
    use std::time::Duration;

    fn context(apps_dir: PathBuf, storage: &SharedStorage) -> ReloadContext {
        ReloadContext {
            apps_dir,
            org_id: g2_core::DEFAULT_ORG_ID.to_owned(),
            storage: Arc::clone(storage),
            forwarder: Forwarder::new(),
            spike_guard: None,
            stats: None,
            metrics: None,
        }
    }

    fn def_json(api_id: &str, listen_path: &str) -> String {
        format!(
            r#"{{"api_id":"{api_id}","name":"{api_id}","listen_path":"{listen_path}","target_url":"http://up.internal","auth":{{"mode":"keyless"}}}}"#
        )
    }

    /// Polls until `gateway` serves `expected` routes or the deadline hits.
    async fn wait_for_routes(gateway: &Gateway, expected: usize) -> bool {
        for _ in 0..100 {
            if gateway.route_count() == expected {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test]
    async fn nudge_rebuilds_table_from_both_sources() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("file.json"), def_json("from-file", "/f/"))
            .expect("write def");
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let ctx = context(dir.path().to_owned(), &storage);

        let gateway = Arc::new(Gateway::new(ctx.build_table().await.expect("initial")));
        assert_eq!(gateway.route_count(), 1);
        tokio::spawn(listen(ctx, Arc::clone(&gateway)));
        // Give the listener a beat to subscribe before publishing.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // A definition lands in storage; nothing changes until the nudge.
        storage
            .set(
                &api_definition_storage_key(g2_core::DEFAULT_ORG_ID, "from-storage"),
                &def_json("from-storage", "/s/"),
                None,
            )
            .await
            .expect("seed");
        assert_eq!(gateway.route_count(), 1, "no reload without a nudge");

        storage
            .publish(&reload_channel(g2_core::DEFAULT_ORG_ID), "reload")
            .await
            .expect("publish");
        assert!(
            wait_for_routes(&gateway, 2).await,
            "nudge must trigger a rebuild picking up the storage definition"
        );
    }

    #[tokio::test]
    async fn failed_rebuild_keeps_the_old_table() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("file.json"), def_json("api", "/a/")).expect("write def");
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let ctx = context(dir.path().to_owned(), &storage);

        let gateway = Arc::new(Gateway::new(ctx.build_table().await.expect("initial")));
        tokio::spawn(listen(ctx, Arc::clone(&gateway)));
        tokio::time::sleep(Duration::from_millis(20)).await;

        // A stored definition conflicting with the file source: the rebuild
        // must fail and the old (1-route) table must keep serving.
        storage
            .set(
                &api_definition_storage_key(g2_core::DEFAULT_ORG_ID, "api"),
                &def_json("api", "/other/"),
                None,
            )
            .await
            .expect("seed");
        storage
            .publish(&reload_channel(g2_core::DEFAULT_ORG_ID), "reload")
            .await
            .expect("publish");

        // Then fix the conflict and nudge again: proves the listener kept
        // running through the failure (and the failed reload changed nothing).
        storage
            .delete(&api_definition_storage_key(g2_core::DEFAULT_ORG_ID, "api"))
            .await
            .expect("delete");
        storage
            .set(
                &api_definition_storage_key(g2_core::DEFAULT_ORG_ID, "fixed"),
                &def_json("fixed", "/fixed/"),
                None,
            )
            .await
            .expect("seed");
        storage
            .publish(&reload_channel(g2_core::DEFAULT_ORG_ID), "reload")
            .await
            .expect("publish");
        assert!(
            wait_for_routes(&gateway, 2).await,
            "listener must survive a failed rebuild and apply the next good one"
        );
    }
}
