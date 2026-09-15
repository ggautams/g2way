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

use g2_middleware::{SharedPluginLoader, SpikeGuard};
use g2_proxy::{Forwarder, Gateway, RouteResources, RouteTable};
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

    /// Producer handle of the analytics channel, if an analytics sink is
    /// configured (one process-wide worker; shared across reloads).
    pub analytics: Option<g2_middleware::AnalyticsHandle>,

    /// WASM plugin loader, if a plugins directory is configured (one
    /// process-wide engine and epoch ticker; shared across reloads —
    /// modules are recompiled per rebuild, which is config-time work).
    pub plugin_loader: Option<SharedPluginLoader>,
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
            &RouteResources {
                spike_guard: self.spike_guard.as_ref(),
                stats: self.stats.as_ref(),
                metrics: self.metrics.as_ref(),
                analytics: self.analytics.as_ref(),
                plugin_loader: self.plugin_loader.as_ref(),
                ..RouteResources::new(&self.forwarder, &self.storage)
            },
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

/// Subscribes to the GraphQL schema-sync channel
/// ([`g2_core::config::graphql_sync_channel`], published by the admin
/// API's `POST /g2/graphql/sync`) and, on every nudge, triggers an
/// immediate introspection re-fetch on every synced API of the gateway's
/// **current** route table (the snapshot is re-read per nudge, so routes
/// from later reloads are covered). Run this on its own task.
///
/// # Errors
///
/// Returns an error only when the initial subscription fails (the storage
/// backend rejected it outright); transport drops after that are retried
/// inside the storage layer.
pub async fn listen_graphql_sync(
    storage: SharedStorage,
    org_id: String,
    gateway: Arc<Gateway>,
) -> Result<(), g2_storage::StorageError> {
    let channel = g2_core::config::graphql_sync_channel(&org_id);
    let mut rx = storage.subscribe(&channel).await?;
    tracing::info!(channel, "listening for graphql schema-sync nudges");
    while rx.recv().await.is_some() {
        let mut triggered = 0usize;
        for route in gateway.routes_snapshot().iter() {
            for handle in route.graphql_sync_handles() {
                handle.trigger();
                triggered += 1;
            }
        }
        tracing::info!(triggered, "graphql schema-sync nudge fanned out");
    }
    tracing::warn!(channel, "graphql schema-sync subscription ended");
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
            analytics: None,
            plugin_loader: None,
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
    async fn graphql_sync_nudge_triggers_every_synced_route() {
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A fake upstream answering introspection, counting hits.
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let counted = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let counted = Arc::clone(&counted);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |_req| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        async move {
                            Ok::<_, std::convert::Infallible>(http::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from_static(
                                    br#"{"data":{"__schema":{"queryType":{"name":"Query"},
                                        "types":[{"kind":"OBJECT","name":"Query","fields":[
                                            {"name":"hello","args":[],
                                             "type":{"kind":"SCALAR","name":"String"}}]},
                                            {"kind":"SCALAR","name":"String"}]}}}"#,
                                )),
                            ))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("gql.json"),
            format!(
                r#"{{"api_id":"gql","name":"gql","listen_path":"/gql/",
                    "target_url":"http://{addr}",
                    "auth":{{"mode":"keyless"}},
                    "graphql":{{"schema":"type Query {{ hello: String }}",
                        "schema_sync":{{"interval_ms":3600000,"timeout_ms":500}}}}}}"#
            ),
        )
        .expect("write def");
        let storage: SharedStorage = Arc::new(MemoryStorage::new());
        let ctx = context(dir.path().to_owned(), &storage);
        let gateway = Arc::new(Gateway::new(ctx.build_table().await.expect("initial")));

        // The spawn-time immediate fetch lands once.
        for _ in 0..200 {
            if hits.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let after_first = hits.load(Ordering::SeqCst);
        assert!(after_first >= 1, "initial introspection never fetched");

        tokio::spawn(listen_graphql_sync(
            Arc::clone(&storage),
            g2_core::DEFAULT_ORG_ID.to_owned(),
            Arc::clone(&gateway),
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;

        // With an hour-long interval, only the nudge explains another hit.
        storage
            .publish(
                &g2_core::config::graphql_sync_channel(g2_core::DEFAULT_ORG_ID),
                "sync",
            )
            .await
            .expect("publish");
        for _ in 0..200 {
            if hits.load(Ordering::SeqCst) > after_first {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("nudge triggered no re-introspection");
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
