//! [`PluginHost`]: the process-wide wasmtime engine and module loader.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;

use g2_core::PluginRef;
use g2_middleware::{HookKind, PluginLoader, SharedPluginExec};
use wasmtime::{Config, Engine, Linker, Module};

use crate::exec::CompiledPlugin;
use crate::EPOCH_TICK_MS;

/// The process-wide plugin host: one wasmtime [`Engine`], the canonicalized
/// plugins directory, and the epoch ticker thread driving plugin timeouts.
///
/// Built once at startup when the gateway has a `plugins_dir`, and shared
/// across route(-table) rebuilds so compiled code caches and the ticker
/// survive hot reloads. Loaded plugins keep the inner state alive; the
/// ticker thread holds only a [`Weak`] reference and exits on its first
/// tick after the host and every plugin are gone (the same lifecycle as the
/// JWKS refresher and upstream health checkers).
pub struct PluginHost {
    inner: Arc<HostInner>,
}

pub(crate) struct HostInner {
    pub(crate) engine: Engine,
    root: PathBuf,
}

impl PluginHost {
    /// Creates the host over `plugins_dir` and starts the epoch ticker.
    ///
    /// # Errors
    ///
    /// Returns a description when the directory does not exist or the
    /// engine cannot be built.
    pub fn new(plugins_dir: &Path) -> Result<Self, String> {
        let root = plugins_dir.canonicalize().map_err(|e| {
            format!(
                "plugins directory `{}` is not usable: {e}",
                plugins_dir.display()
            )
        })?;
        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|e| format!("failed to build engine: {e}"))?;
        let inner = Arc::new(HostInner { engine, root });
        spawn_epoch_ticker(Arc::downgrade(&inner));
        Ok(Self { inner })
    }
}

/// Increments the engine epoch every [`EPOCH_TICK_MS`] so per-store epoch
/// deadlines turn into wall-clock timeouts. Exits once nothing holds the
/// host state any more.
fn spawn_epoch_ticker(inner: Weak<HostInner>) {
    std::thread::Builder::new()
        .name("g2-plugin-epoch".to_owned())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
            match inner.upgrade() {
                Some(inner) => inner.engine.increment_epoch(),
                None => break,
            }
        })
        // Thread spawning only fails when the process is out of resources;
        // plugins would then be the least of its problems. Loudly ignore.
        .map_err(|e| tracing::error!(error = %e, "failed to spawn plugin epoch ticker"))
        .ok();
}

impl PluginLoader for PluginHost {
    fn load(
        &self,
        api_id: &str,
        hook: HookKind,
        plugin: &PluginRef,
    ) -> Result<SharedPluginExec, String> {
        let path = self.resolve(&plugin.path)?;
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("cannot read module `{}`: {e}", plugin.path))?;
        let module = Module::new(&self.inner.engine, &bytes)
            .map_err(|e| format!("module `{}` failed to compile: {e}", plugin.path))?;
        // An empty linker enforces the no-imports sandbox: a module asking
        // for WASI (or anything else) fails right here.
        let linker: Linker<crate::exec::StoreData> = Linker::new(&self.inner.engine);
        let instance_pre = linker.instantiate_pre(&module).map_err(|e| {
            format!(
                "module `{}` declares imports; plugins must be freestanding (no WASI): {e}",
                plugin.path
            )
        })?;
        let compiled = CompiledPlugin::new(Arc::clone(&self.inner), instance_pre, plugin)?;
        compiled.check_abi()?;
        tracing::info!(
            api_id,
            hook = hook.as_str(),
            plugin = plugin.name.as_str(),
            module = plugin.path.as_str(),
            "plugin loaded"
        );
        Ok(Arc::new(compiled))
    }
}

impl PluginHost {
    /// Resolves a validated relative module path strictly inside the
    /// plugins directory, refusing anything (symlinks included) that
    /// escapes it.
    fn resolve(&self, rel: &str) -> Result<PathBuf, String> {
        let joined = self.inner.root.join(rel);
        let path = joined
            .canonicalize()
            .map_err(|e| format!("cannot resolve module `{rel}`: {e}"))?;
        if !path.starts_with(&self.inner.root) {
            return Err(format!(
                "module `{rel}` resolves outside the plugins directory"
            ));
        }
        Ok(path)
    }
}

impl std::fmt::Debug for PluginHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginHost")
            .field("root", &self.inner.root)
            .finish_non_exhaustive()
    }
}
