//! WASM plugin hooks for one API (ADR-0005): custom pre/post request
//! middleware supplied as sandboxed WebAssembly modules.
//!
//! Like [`endpoints`](crate::endpoints), this module is pure configuration —
//! parsing and validation. The runtime lives in `g2-plugin` (the wasmtime
//! host) and `g2-middleware` (`PluginLayer`); modules are compiled at
//! route-build time so the hot path never touches the filesystem or the
//! compiler (ADR-0001).
//!
//! # Semantics
//!
//! `pre` hooks run **before authentication** (they can inject or transform
//! credentials); `post` hooks run **after authentication and rate limiting**
//! (they see the authenticated session's alias). Hooks in a list run in
//! declared order; each may mutate request headers or short-circuit with a
//! full response. A hook failure (trap, timeout, malformed output) rejects
//! the request with `500` — plugins fail **closed**.
//!
//! Module files are resolved strictly inside the gateway's `plugins_dir`
//! ([`crate::GatewayConfig::plugins_dir`]); [`PluginRef::path`] is validated
//! here to be relative and traversal-free, and the host re-checks the
//! canonicalized path at load time. A referenced file that is missing or
//! fails to compile fails the route(-table) build loudly — a hot reload
//! keeps the previous table (ADR-0002 semantics).

use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::Error;

/// Default per-invocation CPU budget, in milliseconds of wall-clock time.
pub const DEFAULT_TIMEOUT_MS: u64 = 50;

/// Ceiling for [`PluginRef::timeout_ms`]: a hook runs inline on a server
/// worker, so its budget stays request-scale.
pub const MAX_TIMEOUT_MS: u64 = 1_000;

/// Default per-invocation linear-memory cap in bytes (16 MiB).
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 16 * 1024 * 1024;

/// Floor for [`PluginRef::max_memory_bytes`]: one 64 KiB wasm page.
pub const MIN_MEMORY_BYTES: u64 = 64 * 1024;

/// Ceiling for [`PluginRef::max_memory_bytes`] (256 MiB).
pub const MAX_MEMORY_BYTES: u64 = 256 * 1024 * 1024;

/// The WASM pre/post hook lists for one API.
///
/// # Example (JSON)
///
/// ```json
/// {
///   "pre": [
///     { "name": "header-tag", "path": "header_tag.wasm",
///       "config": { "header": "x-tenant", "value": "acme" } }
///   ],
///   "post": []
/// }
/// ```
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginsConfig {
    /// Hooks run before authentication, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre: Vec<PluginRef>,

    /// Hooks run after authentication and rate limiting, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post: Vec<PluginRef>,
}

/// One plugin in a hook list: a guest module plus its instance settings.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRef {
    /// Name used in logs and error messages.
    pub name: String,

    /// Path of the `.wasm` module, relative to the gateway's `plugins_dir`.
    /// Absolute paths and `..` components are rejected.
    pub path: String,

    /// Arbitrary JSON handed to the guest verbatim on every invocation.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub config: serde_json::Value,

    /// Wall-clock budget per invocation in milliseconds
    /// (default [`DEFAULT_TIMEOUT_MS`], at most [`MAX_TIMEOUT_MS`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    /// Linear-memory cap per invocation in bytes
    /// (default [`DEFAULT_MAX_MEMORY_BYTES`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_bytes: Option<u64>,
}

impl PluginsConfig {
    /// Validates the block; `api` names the owning definition in errors.
    ///
    /// Checks shape only — whether the referenced module exists and compiles
    /// is decided at route-build time, where a failure keeps the previous
    /// route table (ADR-0002).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidApiDefinition`] when both lists are empty or
    /// any [`PluginRef`] is invalid.
    pub fn validate(&self, api: &str) -> Result<(), Error> {
        if self.pre.is_empty() && self.post.is_empty() {
            return Err(Error::InvalidApiDefinition {
                api: api.to_owned(),
                reason: "`plugins` must declare at least one `pre` or `post` hook \
                         (omit the block entirely for no plugins)"
                    .to_owned(),
            });
        }
        for (list, refs) in [("pre", &self.pre), ("post", &self.post)] {
            for (index, plugin) in refs.iter().enumerate() {
                plugin.validate(api, list, index)?;
            }
        }
        Ok(())
    }
}

impl PluginRef {
    /// Effective per-invocation timeout in milliseconds.
    #[must_use]
    pub fn effective_timeout_ms(&self) -> u64 {
        self.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)
    }

    /// Effective per-invocation linear-memory cap in bytes.
    #[must_use]
    pub fn effective_max_memory_bytes(&self) -> u64 {
        self.max_memory_bytes.unwrap_or(DEFAULT_MAX_MEMORY_BYTES)
    }

    fn validate(&self, api: &str, list: &str, index: usize) -> Result<(), Error> {
        let fail = |reason: String| Error::InvalidApiDefinition {
            api: api.to_owned(),
            reason: format!("`plugins.{list}[{index}]` {reason}"),
        };
        if self.name.trim().is_empty() {
            return Err(fail("`name` must not be empty".to_owned()));
        }
        if let Err(reason) = check_module_path(&self.path) {
            return Err(fail(format!("`path` {reason}")));
        }
        if let Some(ms) = self.timeout_ms {
            if ms == 0 || ms > MAX_TIMEOUT_MS {
                return Err(fail(format!(
                    "`timeout_ms` must be between 1 and {MAX_TIMEOUT_MS} (got {ms})"
                )));
            }
        }
        if let Some(bytes) = self.max_memory_bytes {
            if !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&bytes) {
                return Err(fail(format!(
                    "`max_memory_bytes` must be between {MIN_MEMORY_BYTES} and \
                     {MAX_MEMORY_BYTES} (got {bytes})"
                )));
            }
        }
        Ok(())
    }
}

/// Checks that a module path is a plain relative path inside the plugins
/// directory: non-empty, not absolute, no `..`/prefix components, no
/// backslashes and no NUL bytes. Returns a reason fragment on failure.
fn check_module_path(path: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("must not be empty".to_owned());
    }
    if path.contains('\\') {
        return Err("must use `/` separators (backslash rejected)".to_owned());
    }
    if path.contains('\0') {
        return Err("must not contain NUL bytes".to_owned());
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return Err("must be relative to the plugins directory".to_owned());
    }
    for component in p.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err("must not contain `..` components".to_owned());
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err("must be relative to the plugins directory".to_owned());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(path: &str) -> PluginRef {
        PluginRef {
            name: "test".to_owned(),
            path: path.to_owned(),
            config: serde_json::Value::Null,
            timeout_ms: None,
            max_memory_bytes: None,
        }
    }

    fn config_with(pre: Vec<PluginRef>, post: Vec<PluginRef>) -> PluginsConfig {
        PluginsConfig { pre, post }
    }

    #[test]
    fn minimal_json_round_trips_with_defaults() {
        let cfg: PluginsConfig =
            serde_json::from_str(r#"{"pre":[{"name":"a","path":"a.wasm"}]}"#).expect("parse");
        assert_eq!(cfg.pre.len(), 1);
        assert!(cfg.post.is_empty());
        let p = &cfg.pre[0];
        assert!(p.config.is_null());
        assert_eq!(p.effective_timeout_ms(), DEFAULT_TIMEOUT_MS);
        assert_eq!(p.effective_max_memory_bytes(), DEFAULT_MAX_MEMORY_BYTES);
        let json = serde_json::to_value(&cfg).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({"pre":[{"name":"a","path":"a.wasm"}]})
        );
        cfg.validate("api").expect("valid");
    }

    #[test]
    fn config_json_is_carried_verbatim() {
        let cfg: PluginsConfig = serde_json::from_str(
            r#"{"post":[{"name":"a","path":"a.wasm","config":{"k":[1,2],"s":"x"}}]}"#,
        )
        .expect("parse");
        assert_eq!(cfg.post[0].config, serde_json::json!({"k":[1,2],"s":"x"}));
        cfg.validate("api").expect("valid");
    }

    #[test]
    fn empty_block_is_rejected() {
        let err = config_with(vec![], vec![]).validate("api").unwrap_err();
        assert!(err.to_string().contains("at least one"), "{err}");
    }

    #[test]
    fn empty_name_is_rejected() {
        let mut p = plugin("a.wasm");
        p.name = "  ".to_owned();
        let err = config_with(vec![p], vec![]).validate("api").unwrap_err();
        assert!(err.to_string().contains("`plugins.pre[0]` `name`"), "{err}");
    }

    #[test]
    fn traversal_and_absolute_paths_are_rejected() {
        for bad in [
            "",
            "  ",
            "../evil.wasm",
            "a/../../evil.wasm",
            "/abs/evil.wasm",
            "a\\b.wasm",
            "a\0.wasm",
        ] {
            let err = config_with(vec![], vec![plugin(bad)])
                .validate("api")
                .unwrap_err();
            assert!(
                err.to_string().contains("`plugins.post[0]` `path`"),
                "path {bad:?}: {err}"
            );
        }
        // Plain nested relative paths stay allowed.
        config_with(vec![], vec![plugin("sub/dir/ok.wasm")])
            .validate("api")
            .expect("nested relative path is valid");
    }

    #[test]
    fn timeout_bounds_are_enforced() {
        for (ms, ok) in [
            (0, false),
            (1, true),
            (MAX_TIMEOUT_MS, true),
            (1_001, false),
        ] {
            let mut p = plugin("a.wasm");
            p.timeout_ms = Some(ms);
            let result = config_with(vec![p], vec![]).validate("api");
            assert_eq!(result.is_ok(), ok, "timeout_ms={ms}");
        }
    }

    #[test]
    fn memory_bounds_are_enforced() {
        for (bytes, ok) in [
            (MIN_MEMORY_BYTES - 1, false),
            (MIN_MEMORY_BYTES, true),
            (MAX_MEMORY_BYTES, true),
            (MAX_MEMORY_BYTES + 1, false),
        ] {
            let mut p = plugin("a.wasm");
            p.max_memory_bytes = Some(bytes);
            let result = config_with(vec![p], vec![]).validate("api");
            assert_eq!(result.is_ok(), ok, "max_memory_bytes={bytes}");
        }
    }

    #[test]
    fn error_names_the_list_and_index() {
        let err = config_with(vec![plugin("a.wasm"), plugin("../b.wasm")], vec![])
            .validate("api")
            .unwrap_err();
        assert!(err.to_string().contains("`plugins.pre[1]`"), "{err}");
    }
}
