//! [`CompiledPlugin`]: one loaded module, run per request in a fresh store.

use std::sync::Arc;

use g2_middleware::{HookInvocation, HookOutcome, PluginExec};
use serde_json::value::RawValue;
use wasmtime::{InstancePre, Store, StoreLimits, StoreLimitsBuilder, Trap};

use crate::abi;
use crate::host::HostInner;
use crate::EPOCH_TICK_MS;

/// Per-store state: only the resource limiter.
pub(crate) struct StoreData {
    limits: StoreLimits,
}

/// One compiled, pre-linked plugin. Each invocation instantiates it into a
/// fresh [`Store`] — no state survives between requests, and dropping the
/// store reclaims all guest memory (which is why the ABI has no `g2_free`).
pub(crate) struct CompiledPlugin {
    /// Keeps the engine (and its epoch ticker) alive while any plugin lives.
    host: Arc<HostInner>,
    instance_pre: InstancePre<StoreData>,
    name: String,
    /// The plugin's `config` JSON, serialized once at load time.
    config: Box<RawValue>,
    timeout_ms: u64,
    /// Epoch ticks equivalent to `timeout_ms`, precomputed.
    deadline_ticks: u64,
    max_memory_bytes: usize,
}

impl CompiledPlugin {
    pub(crate) fn new(
        host: Arc<HostInner>,
        instance_pre: InstancePre<StoreData>,
        plugin: &g2_core::PluginRef,
    ) -> Result<Self, String> {
        let config = RawValue::from_string(plugin.config.to_string())
            .map_err(|e| format!("plugin `{}` config is not serializable: {e}", plugin.name))?;
        let timeout_ms = plugin.effective_timeout_ms();
        Ok(Self {
            host,
            instance_pre,
            name: plugin.name.clone(),
            config,
            timeout_ms,
            deadline_ticks: timeout_ms.div_ceil(EPOCH_TICK_MS) + 1,
            max_memory_bytes: usize::try_from(plugin.effective_max_memory_bytes())
                .unwrap_or(usize::MAX),
        })
    }

    /// A fresh store with this plugin's memory cap and epoch deadline set.
    fn new_store(&self) -> Store<StoreData> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.max_memory_bytes)
            .memories(1)
            .instances(1)
            .tables(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&self.host.engine, StoreData { limits });
        store.limiter(|data| &mut data.limits);
        store.set_epoch_deadline(self.deadline_ticks);
        store
    }

    /// Load-time handshake: instantiates once, checks the required exports
    /// exist with the right signatures, and verifies `g2_abi_version`.
    pub(crate) fn check_abi(&self) -> Result<(), String> {
        let mut store = self.new_store();
        let instance = self
            .instance_pre
            .instantiate(&mut store)
            .map_err(|e| self.describe_error(&e))?;
        instance
            .get_memory(&mut store, "memory")
            .ok_or("module does not export `memory`")?;
        instance
            .get_typed_func::<i32, i32>(&mut store, "g2_alloc")
            .map_err(|e| format!("bad `g2_alloc` export: {e}"))?;
        instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "g2_hook")
            .map_err(|e| format!("bad `g2_hook` export: {e}"))?;
        let version = instance
            .get_typed_func::<(), i32>(&mut store, "g2_abi_version")
            .map_err(|e| format!("bad `g2_abi_version` export: {e}"))?
            .call(&mut store, ())
            .map_err(|e| self.describe_error(&e))?;
        if version != crate::ABI_VERSION {
            return Err(format!(
                "module speaks ABI version {version}; this gateway speaks {}",
                crate::ABI_VERSION
            ));
        }
        Ok(())
    }

    /// Classifies a wasmtime error into the plugin failure message.
    fn describe_error(&self, err: &wasmtime::Error) -> String {
        match err.downcast_ref::<Trap>() {
            Some(Trap::Interrupt) => {
                format!("timed out after {}ms", self.timeout_ms)
            }
            Some(trap) => format!("guest trapped: {trap}"),
            None => format!("guest failed: {err:#}"),
        }
    }
}

impl PluginExec for CompiledPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(&self, call: &HookInvocation<'_>) -> Result<HookOutcome, String> {
        let input = abi::encode_input(call, &self.config)?;
        let input_len = i32::try_from(input.len())
            .map_err(|_| "hook input exceeds guest address space".to_owned())?;

        let mut store = self.new_store();
        let instance = self
            .instance_pre
            .instantiate(&mut store)
            .map_err(|e| self.describe_error(&e))?;
        // Presence and signatures were verified at load time; a module
        // cannot change exports afterwards, so failures here are unreachable
        // in practice but still reported, never unwrapped.
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or("module does not export `memory`")?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "g2_alloc")
            .map_err(|e| format!("bad `g2_alloc` export: {e}"))?;
        let hook = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "g2_hook")
            .map_err(|e| format!("bad `g2_hook` export: {e}"))?;

        let ptr = alloc
            .call(&mut store, input_len)
            .map_err(|e| self.describe_error(&e))?;
        let ptr = usize::try_from(u32::from_ne_bytes(ptr.to_ne_bytes()))
            .map_err(|_| "g2_alloc returned an unusable pointer".to_owned())?;
        // Bounds-check against the memory size *after* the alloc call — the
        // guest may have grown its memory to satisfy it.
        if ptr
            .checked_add(input.len())
            .is_none_or(|end| end > memory.data_size(&store))
        {
            return Err("g2_alloc returned an out-of-bounds buffer".to_owned());
        }
        memory
            .write(&mut store, ptr, &input)
            .map_err(|e| format!("failed to write hook input: {e}"))?;

        let packed = hook
            .call(
                &mut store,
                (i32::try_from(ptr).unwrap_or(i32::MAX), input_len),
            )
            .map_err(|e| self.describe_error(&e))?;
        let packed = u64::from_ne_bytes(packed.to_ne_bytes());
        let out_ptr = usize::try_from(packed >> 32).unwrap_or(usize::MAX);
        let out_len = usize::try_from(packed & 0xffff_ffff).unwrap_or(usize::MAX);
        let data = memory.data(&store);
        let out = out_ptr
            .checked_add(out_len)
            .and_then(|end| data.get(out_ptr..end))
            .ok_or("guest returned an out-of-bounds output buffer")?;
        abi::decode_output(out)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::time::{Duration, Instant};

    use g2_middleware::{HookKind, PluginLoader};
    use http::{HeaderMap, HeaderValue, Method};

    use super::*;
    use crate::PluginHost;

    /// Writes `wat` as a compiled module into `dir` and returns a
    /// [`g2_core::PluginRef`] for it.
    fn install(dir: &std::path::Path, file: &str, wat: &str) -> g2_core::PluginRef {
        let wasm = wat::parse_str(wat).expect("valid WAT");
        let mut f = std::fs::File::create(dir.join(file)).expect("create module");
        f.write_all(&wasm).expect("write module");
        plugin_ref(file)
    }

    fn plugin_ref(file: &str) -> g2_core::PluginRef {
        serde_json::from_value(serde_json::json!({"name": file, "path": file})).expect("plugin ref")
    }

    fn invocation(headers: &HeaderMap) -> HookInvocation<'_> {
        HookInvocation {
            kind: HookKind::Pre,
            api_id: "users",
            org_id: "default",
            method: &Method::GET,
            path: "/users/1",
            query: None,
            headers,
            client_addr: None,
            session_alias: None,
        }
    }

    /// A guest that ignores its input and returns `output` verbatim from a
    /// data segment. `g2_alloc` hands out memory above the segment.
    fn static_guest(output: &str) -> String {
        assert!(!output.contains('"') || output.contains('\u{22}'));
        let escaped = output.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            r#"(module
              (memory (export "memory") 4)
              (func (export "g2_abi_version") (result i32) i32.const 1)
              (func (export "g2_alloc") (param i32) (result i32) i32.const 65536)
              (data (i32.const 0) "{escaped}")
              (func (export "g2_hook") (param i32 i32) (result i64)
                i64.const {len}))
            "#,
            len = output.len(),
        )
    }

    fn load_and_run(wat: &str) -> Result<HookOutcome, String> {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = PluginHost::new(dir.path()).expect("host");
        let plugin = install(dir.path(), "guest.wasm", wat);
        let exec = host.load("users", HookKind::Pre, &plugin)?;
        let headers = HeaderMap::new();
        exec.run(&invocation(&headers))
    }

    #[test]
    fn static_continue_guest_mutates_headers() {
        let outcome = load_and_run(&static_guest(
            r#"{"action":"continue","set_headers":[["x-from-plugin","yes"]],"remove_headers":["x-internal"]}"#,
        ))
        .expect("run");
        match outcome {
            HookOutcome::Continue {
                set_headers,
                remove_headers,
            } => {
                assert_eq!(set_headers[0].0.as_str(), "x-from-plugin");
                assert_eq!(remove_headers[0].as_str(), "x-internal");
            }
            HookOutcome::Respond(_) => panic!("expected continue"),
        }
    }

    #[test]
    fn static_respond_guest_short_circuits() {
        let outcome = load_and_run(&static_guest(
            r#"{"action":"respond","response":{"status":418,"body":"teapot"}}"#,
        ))
        .expect("run");
        match outcome {
            HookOutcome::Respond(resp) => {
                assert_eq!(resp.status().as_u16(), 418);
                assert_eq!(resp.body().as_ref(), b"teapot");
            }
            HookOutcome::Continue { .. } => panic!("expected respond"),
        }
    }

    #[test]
    fn malformed_guest_output_is_rejected() {
        let err = load_and_run(&static_guest(r#"{"action":"explode"}"#)).expect_err("reject");
        assert!(err.contains("invalid output JSON"), "{err}");
    }

    #[test]
    fn out_of_bounds_output_is_rejected() {
        // Packed return points 1 GiB into a 4-page memory.
        let err = load_and_run(
            r#"(module
              (memory (export "memory") 4)
              (func (export "g2_abi_version") (result i32) i32.const 1)
              (func (export "g2_alloc") (param i32) (result i32) i32.const 65536)
              (func (export "g2_hook") (param i32 i32) (result i64)
                i64.const 4611686018427387904))
            "#,
        )
        .expect_err("reject");
        assert!(err.contains("out-of-bounds output"), "{err}");
    }

    #[test]
    fn infinite_loop_traps_at_the_timeout() {
        let start = Instant::now();
        let err = load_and_run(
            r#"(module
              (memory (export "memory") 4)
              (func (export "g2_abi_version") (result i32) i32.const 1)
              (func (export "g2_alloc") (param i32) (result i32) i32.const 65536)
              (func (export "g2_hook") (param i32 i32) (result i64)
                (loop $spin br $spin)
                unreachable))
            "#,
        )
        .expect_err("must time out");
        assert!(err.contains("timed out after 50ms"), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "trap took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn oversized_memory_fails_under_the_cap() {
        // 200 pages = 12.5 MiB minimum; cap it at 1 MiB.
        let dir = tempfile::tempdir().expect("tempdir");
        let host = PluginHost::new(dir.path()).expect("host");
        let mut plugin = install(
            dir.path(),
            "big.wasm",
            r#"(module
              (memory (export "memory") 200)
              (func (export "g2_abi_version") (result i32) i32.const 1)
              (func (export "g2_alloc") (param i32) (result i32) i32.const 0)
              (func (export "g2_hook") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        plugin.max_memory_bytes = Some(1024 * 1024);
        let err = host
            .load("users", HookKind::Pre, &plugin)
            .err()
            .expect("must fail to load");
        assert!(
            err.to_lowercase().contains("memory") || err.contains("exceeds"),
            "{err}"
        );
    }

    #[test]
    fn missing_hook_export_fails_at_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = PluginHost::new(dir.path()).expect("host");
        let plugin = install(
            dir.path(),
            "nohook.wasm",
            r#"(module
              (memory (export "memory") 1)
              (func (export "g2_abi_version") (result i32) i32.const 1)
              (func (export "g2_alloc") (param i32) (result i32) i32.const 0))
            "#,
        );
        let err = host
            .load("users", HookKind::Pre, &plugin)
            .err()
            .expect("fail");
        assert!(err.contains("g2_hook"), "{err}");
    }

    #[test]
    fn wrong_abi_version_fails_at_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = PluginHost::new(dir.path()).expect("host");
        let plugin = install(
            dir.path(),
            "v2.wasm",
            r#"(module
              (memory (export "memory") 1)
              (func (export "g2_abi_version") (result i32) i32.const 2)
              (func (export "g2_alloc") (param i32) (result i32) i32.const 0)
              (func (export "g2_hook") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        let err = host
            .load("users", HookKind::Pre, &plugin)
            .err()
            .expect("fail");
        assert!(err.contains("ABI version 2"), "{err}");
    }

    #[test]
    fn imports_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = PluginHost::new(dir.path()).expect("host");
        let plugin = install(
            dir.path(),
            "wasi.wasm",
            r#"(module
              (import "wasi_snapshot_preview1" "proc_exit" (func (param i32)))
              (memory (export "memory") 1)
              (func (export "g2_abi_version") (result i32) i32.const 1)
              (func (export "g2_alloc") (param i32) (result i32) i32.const 0)
              (func (export "g2_hook") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        let err = host
            .load("users", HookKind::Pre, &plugin)
            .err()
            .expect("fail");
        assert!(err.contains("freestanding"), "{err}");
    }

    #[test]
    fn missing_file_and_garbage_bytes_fail_at_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = PluginHost::new(dir.path()).expect("host");
        let err = host
            .load("users", HookKind::Pre, &plugin_ref("absent.wasm"))
            .err()
            .expect("fail");
        assert!(err.contains("cannot resolve module"), "{err}");

        std::fs::write(dir.path().join("garbage.wasm"), b"not wasm").expect("write");
        let err = host
            .load("users", HookKind::Pre, &plugin_ref("garbage.wasm"))
            .err()
            .expect("fail");
        assert!(err.contains("failed to compile"), "{err}");
    }

    #[test]
    fn escaping_symlinks_are_refused() {
        let outside = tempfile::tempdir().expect("outside dir");
        let wasm = wat::parse_str(static_guest(r#"{"action":"continue"}"#)).expect("wat");
        std::fs::write(outside.path().join("real.wasm"), &wasm).expect("write");

        let dir = tempfile::tempdir().expect("plugins dir");
        std::os::unix::fs::symlink(
            outside.path().join("real.wasm"),
            dir.path().join("link.wasm"),
        )
        .expect("symlink");
        let host = PluginHost::new(dir.path()).expect("host");
        let err = host
            .load("users", HookKind::Pre, &plugin_ref("link.wasm"))
            .err()
            .expect("fail");
        assert!(err.contains("outside the plugins directory"), "{err}");
    }

    /// End-to-end input-delivery proof: a real (hand-written WAT) guest that
    /// scans its input bytes for a marker and answers 418 iff found.
    #[test]
    fn needle_scan_guest_reads_real_input() {
        // Guest: alloc at 4096; on hook, scan the input for the byte
        // sequence "x-needle" and return one of two static outputs.
        let found = r#"{"action":"respond","response":{"status":418}}"#;
        let not_found = r#"{"action":"continue"}"#;
        let needle = b"x-needle";
        let wat = format!(
            r#"(module
              (memory (export "memory") 4)
              (func (export "g2_abi_version") (result i32) i32.const 1)
              (func (export "g2_alloc") (param i32) (result i32) i32.const 4096)
              (data (i32.const 0) "{found_esc}")
              (data (i32.const 256) "{notfound_esc}")
              (data (i32.const 512) "{needle_str}")
              (func $matches_at (param $p i32) (result i32)
                (local $i i32)
                (block $no
                  (loop $next
                    (br_if $no
                      (i32.ne
                        (i32.load8_u (i32.add (local.get $p) (local.get $i)))
                        (i32.load8_u (i32.add (i32.const 512) (local.get $i)))))
                    (local.set $i (i32.add (local.get $i) (i32.const 1)))
                    (br_if $next (i32.lt_u (local.get $i) (i32.const {needle_len})))
                  )
                  (return (i32.const 1)))
                i32.const 0)
              (func (export "g2_hook") (param $ptr i32) (param $len i32) (result i64)
                (local $p i32)
                (local $end i32)
                (local.set $p (local.get $ptr))
                (local.set $end
                  (i32.sub (i32.add (local.get $ptr) (local.get $len))
                           (i32.const {needle_len})))
                (block $done
                  (loop $scan
                    (br_if $done (i32.gt_u (local.get $p) (local.get $end)))
                    (if (call $matches_at (local.get $p))
                      (then (return (i64.const {found_len}))))
                    (local.set $p (i32.add (local.get $p) (i32.const 1)))
                    (br $scan)))
                ;; not found: ptr 256, len of the continue doc
                (i64.or
                  (i64.shl (i64.const 256) (i64.const 32))
                  (i64.const {notfound_len})))
            )"#,
            found_esc = found.replace('"', "\\\""),
            notfound_esc = not_found.replace('"', "\\\""),
            needle_str = std::str::from_utf8(needle).expect("ascii"),
            needle_len = needle.len(),
            found_len = found.len(),
            notfound_len = not_found.len(),
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let host = PluginHost::new(dir.path()).expect("host");
        let plugin = install(dir.path(), "scan.wasm", &wat);
        let exec = host.load("users", HookKind::Pre, &plugin).expect("load");

        let mut headers = HeaderMap::new();
        headers.insert("x-needle", HeaderValue::from_static("present"));
        match exec.run(&invocation(&headers)).expect("run") {
            HookOutcome::Respond(resp) => assert_eq!(resp.status().as_u16(), 418),
            HookOutcome::Continue { .. } => panic!("marker header not seen by guest"),
        }

        let headers = HeaderMap::new();
        match exec.run(&invocation(&headers)).expect("run") {
            HookOutcome::Continue { .. } => {}
            HookOutcome::Respond(_) => panic!("guest matched without the marker"),
        }
    }
}
