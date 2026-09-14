# WASM plugins (pre/post request hooks)

g2way runs user-supplied WebAssembly modules as per-API request hooks —
custom middleware, sandboxed:

- **`pre` hooks** run before authentication: inject or transform
  credentials, tag requests, reject early.
- **`post` hooks** run after authentication and rate limiting: they see
  the authenticated session's alias and run before any transform touches
  the upstream-bound request.
- A hook can **mutate request headers** or **short-circuit** the request
  with a full response. It cannot read or write bodies (v1 limit).
- Guests are fully sandboxed: no WASI, no filesystem/network/clock, a
  wall-clock timeout and a memory cap per invocation.

Design decisions live in [ADR-0005](adr/0005-wasm-plugins.md). A minimal
example guest lives in `examples/plugins/`.

## Configuration

Plugins are enabled by pointing the gateway at a module directory:

| Knob | Flag / env | Meaning |
|---|---|---|
| `plugins_dir` | `--plugins-dir` / `G2_PLUGINS_DIR` | Directory of `.wasm` modules. Unset (default) = plugins disabled; a definition referencing one then fails to load. |

Each API opts in with a `plugins` block:

```json
{
  "api_id": "users",
  "name": "Users API",
  "listen_path": "/users/",
  "target_url": "http://users.internal:8000/",
  "auth": { "mode": "auth_token" },
  "plugins": {
    "pre": [
      { "name": "tenant-tag",
        "path": "tenant_tag.wasm",
        "config": { "header": "x-tenant", "value": "acme" } }
    ],
    "post": [
      { "name": "audit", "path": "audit.wasm", "timeout_ms": 100 }
    ]
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `pre` / `post` | `[]` | Hook lists, run in declared order. A present `plugins` block must declare at least one hook. |
| `name` | — | Required. Names the plugin in logs and errors. |
| `path` | — | Required. Module path **relative to `plugins_dir`**; absolute paths and `..` are rejected, and symlinks may not escape the directory. |
| `config` | `null` | Arbitrary JSON handed to the guest verbatim on every invocation. |
| `timeout_ms` | `50` | Wall-clock budget per invocation (1–1000). |
| `max_memory_bytes` | `16777216` (16 MiB) | Guest linear-memory cap per invocation (64 KiB–256 MiB). |

### Semantics

- **Pre runs just before auth; post runs just after rate limiting.** A
  blocked path, an oversized body or a denied IP rejects the request
  before any plugin runs; a 401/403/429 rejects it before any *post*
  plugin runs. Both slots run before header transforms, GraphQL policing,
  mocks and the cache.
- **Hooks fail closed.** A trap, timeout, memory-cap hit or malformed
  output answers `500 {"error":"plugin execution failed"}` and logs the
  plugin's name — a broken plugin never silently waves traffic through.
- **Header sets use insert semantics** (an existing header of the same
  name is replaced); removals run before sets. Later plugins and inner
  layers see earlier plugins' mutations.
- **Plugins cannot spoof `x-g2-api-id`** — the anti-spoof stamp is applied
  after every plugin and transform, directly before forwarding.
- **Short-circuit responses get CORS decoration** (the CORS layer sits
  outside both slots) but, like every gateway rejection, are **not**
  header-transformed.
- **Versioning**: `VersionOverrides.plugins` replaces the whole block for
  that version (`{"plugins": {"pre": []}}` would still be rejected as
  empty — omit the override to inherit, or declare real hooks).
- **Caching**: the response cache keys on method + path + query only.
  Request headers set by plugins do not vary cache keys; avoid combining
  `cache` with plugins whose effect varies the *response* per client.
- **Loading is fail-loud**: a missing or broken module fails startup, and
  fails a hot reload while the previous route table keeps serving. Modules
  are (re)compiled at each route build, never per request.

## The guest ABI (version 1)

A plugin is a **freestanding core wasm module** — zero imports (a module
asking for WASI is refused at load) — with four exports:

| Export | Signature | Contract |
|---|---|---|
| `memory` | linear memory | shared with the host |
| `g2_abi_version` | `() -> i32` | return `1` |
| `g2_alloc` | `(len: i32) -> i32` | return a pointer to `len` writable bytes |
| `g2_hook` | `(ptr: i32, len: i32) -> i64` | run the hook on the input at `ptr..ptr+len`; return `(out_ptr << 32) \| out_len` |

Per invocation the host calls `g2_alloc`, writes the JSON input document,
calls `g2_hook`, and reads the JSON output document from the returned
location. Each invocation runs in a fresh instance that is discarded
afterwards — there is no `g2_free`, and guests may bump-allocate.

Input document:

```json
{
  "abi_version": 1,
  "hook": "pre",
  "api_id": "users", "org_id": "default",
  "plugin_config": { "header": "x-tenant", "value": "acme" },
  "request": {
    "method": "GET",
    "path": "/users/1",
    "query": "page=2",
    "headers": [["host", "example.com"], ["x-multi", "a"], ["x-multi", "b"]],
    "client_addr": "203.0.113.9:41200"
  },
  "session": { "alias": "acme-mobile-app" }
}
```

`path` is the full client path (listen path included), `query` and
`client_addr` may be `null`, repeated header pairs carry multi-valued
headers, and `session` is non-`null` only for post hooks on authenticated
requests.

Output document — exactly one of:

```json
{ "action": "continue",
  "set_headers": [["x-user", "42"]],
  "remove_headers": ["x-internal"] }
```

```json
{ "action": "respond",
  "response": { "status": 403,
                "headers": [["content-type", "text/plain"]],
                "body": "denied" } }
```

`set_headers`/`remove_headers` default to empty; `status` must be
100–599; `body` is a UTF-8 string (binary bodies are a future ABI
extension). Anything malformed — bad JSON, invalid header names/values,
an out-of-bounds pointer — fails the request closed.

## Writing a plugin in Rust

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib"]
```

```rust
use std::alloc::{alloc, Layout};

#[no_mangle]
pub extern "C" fn g2_abi_version() -> i32 { 1 }

#[no_mangle]
pub extern "C" fn g2_alloc(len: i32) -> i32 {
    let layout = Layout::from_size_align(len as usize, 1).unwrap();
    unsafe { alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn g2_hook(ptr: i32, len: i32) -> i64 {
    let input = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, len as usize)
    };
    let _request: serde_json::Value = serde_json::from_slice(input).unwrap();
    let out = br#"{"action":"continue","set_headers":[["x-from-plugin","yes"]]}"#;
    let out_ptr = g2_alloc(out.len() as i32);
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), out_ptr as *mut u8, out.len());
    }
    ((out_ptr as i64) << 32) | out.len() as i64
}
```

```sh
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/my_plugin.wasm "$PLUGINS_DIR/"
```

Any language that emits freestanding wasm works the same way — the whole
contract is the four exports and the two JSON documents above.

## Verification

- `crates/g2way/tests/plugin_e2e.rs` drives WAT-compiled guests through a
  real gateway: header mutation visible at the upstream, short-circuits
  (upstream untouched), pre-before-auth vs post-after-auth, declared-order
  execution, off-by-default, and broken-module build failures.
- `g2-plugin` unit tests cover the ABI (round-trips, every malformed-output
  rejection) and the sandbox: infinite loops trap at the timeout, memory
  over the cap fails, imports/missing exports/wrong ABI version fail at
  load, and escaping symlinks are refused.
- `g2-middleware` tests pin the chain positions (pre answers before auth's
  401; post never runs on one) and the `x-g2-api-id` anti-spoof invariant.

## Limitations

- No request/response body access; no response-header mutation on
  `continue`. Both are candidate ABI v2 powers.
- No WASI: no filesystem, network, clocks, or randomness inside guests.
- Hooks run inline on the serving task; the per-request worst case is the
  sum of the API's plugin timeouts.
- Modules recompile on every route build; very large plugin sets may
  slow reloads (a compile cache is noted future work).
- Plugin `config` changes require a reload nudge like any definition
  change (storage-sourced) or a restart (file-sourced).
