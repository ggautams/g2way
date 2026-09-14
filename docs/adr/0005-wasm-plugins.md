# ADR-0005: WASM plugin system (pre/post request hooks)

Date: 2026-09-01 · Status: accepted

## Context

Operators need to attach custom middleware to an API (pre and post
hooks). g2way's M8+ box is a plugin system with
WASM pre/post hooks: per-API guest modules that run inside the gateway,
inspect a request, mutate its headers, or answer it outright. This is the
first feature executing user-supplied code in the proxy path, which forces
decisions about the runtime, the guest interface, sandboxing, failure
semantics, and where the new dependency weight lands. Confirmed v1 scope:
custom ABI, header mutation + short-circuit responses only — no body
access, which would force request buffering (ADR-0004's machinery) and is
its own future box.

## Decisions

1. **Runtime: wasmtime, pinned to major 33, with trimmed features**
   (`default-features = false`, `runtime` + `cranelift` + `std`). Wasmtime
   is the reference Bytecode Alliance runtime: mature sandboxing,
   epoch-based interruption (the timeout mechanism below), and the natural
   on-ramp to a component-model ABI later. The pin matters twice over: 33
   is the last major whose MSRV (1.85) matches the workspace
   `rust-version`, and the trimmed feature set keeps cmake-needing
   dependencies out of the `rust:1-slim` Docker build (verified: no
   cmake/zstd anywhere in `cargo tree -p g2-plugin`). Considered:
   **wasmi** (pure-Rust interpreter, much lighter — but 10–100× slower,
   cheap insurance against plugins growing beyond header work, and its
   fuel metering maps poorly to wall-clock timeouts), **wasmer** (heavier,
   licensing churn), native dynamic libraries (no sandbox at all).

2. **A purpose-built JSON-over-linear-memory ABI, versioned from day
   one.** A guest is a freestanding core module exporting `memory`,
   `g2_abi_version() -> i32` (checked `== 1` at load), `g2_alloc(len) ->
   ptr` and `g2_hook(ptr, len) -> i64` (packed `ptr<<32|len`). The host
   writes a JSON input document (hook kind, api/org ids, the plugin's
   `config` JSON verbatim, method/path/query/headers/client address, and
   the session alias for post hooks) and reads a JSON output document
   (`continue` with header mutations, or `respond` with a full response).
   JSON costs a few microseconds per call but makes plugins writable in
   any language that compiles to wasm with no g2way-specific bindings, and
   hand-writable in WAT for tests. There is deliberately no `g2_free`:
   every invocation runs in a throwaway instance (decision 3), so guests
   may bump-allocate. Considered: the **proxy-wasm ABI** (Envoy ecosystem
   compatibility, but a large spec with immature Rust host support — far
   more surface than two hooks justify), the **component model / WIT**
   (typed and multi-language, but guests then need wit-bindgen tooling and
   test fixtures can't be hand-written; recorded as the plausible v2
   direction), **flat binary structs** (faster, but brittle across
   languages and versions).

3. **Synchronous inline execution, epoch deadlines, a fresh `Store` per
   invocation, zero imports.** Hooks run inline on the serving task: they
   are header-scale work, and the worst case is bounded by the epoch
   deadline (default 50 ms, max 1000 ms) driven by one process-wide 5 ms
   ticker thread — epoch checks cost a compare at loop back-edges, and
   unlike fuel they express wall-clock budgets directly. Each invocation
   instantiates the pre-linked module (`InstancePre`) into a fresh store
   with a `StoreLimits` memory cap (default 16 MiB, grow failures trap),
   so no state leaks between requests and cleanup is dropping the store.
   Modules are linked against an **empty linker**: a plugin has no WASI,
   no filesystem, no network, no clock — pure compute over the request
   view. Per-request instantiation is payload work on APIs that opted in
   (ADR-0004's distinction); module compilation happens at route-build
   time. Considered: `spawn_blocking` (a thread-pool handoff per request,
   queueing under load), wasmtime's async fibers (dependency weight for
   no benefit while there are no host imports), fuel metering (indirect
   timeout semantics).

4. **Plugins fail closed.** A trap, timeout, memory-cap hit, or malformed
   output rejects the request with `500` (logged with the plugin name;
   generic body). The rate limiter's storage errors fail *open* because a
   broken limiter only weakens capacity protection while auth still
   stands; a pre hook may *be* the auth-adjacent security control, so
   failing open would silently disable whatever the operator bolted on.
   Considered: fail-open (rejected for exactly that reason), configurable
   per plugin (deferred until someone needs it).

5. **Dependency placement: wasmtime lives in a new `g2-plugin` crate;
   `g2-middleware` and `g2-proxy` stay wasm-free.** g2-middleware defines
   the `PluginExec`/`PluginLoader` traits and the `PluginLayer` (tested
   with in-memory fakes — the `JwksFetch` inversion again); g2-plugin
   implements them over wasmtime; only the binary (which constructs the
   `PluginHost`, like the rustls acceptor per ADR-0003) and its e2e tests
   link the runtime. g2-core carries only the config types. Considered:
   wasmtime directly in g2-middleware (every consumer pays the compile),
   the layer in g2-plugin (would drag proxy-path types out of
   g2-middleware).

6. **Chain slots: pre directly above auth (item 10), post directly below
   rate limiting (item 13); both per-version.** Pre sits above auth so
   hooks can inject or transform credentials, below
   the path/size policies so statically-rejected requests never buy wasm
   CPU (the GraphQL layer's "rejections buy no parse work" rationale), and
   below CORS so short-circuits still get decorated. Post sits below
   auth/rate-limit so it sees the session and 401/403/429 rejections never
   invoke it, and above GraphQL/header transforms so hook decisions run
   before payload work and hook rejections stay untransformed. Both sit
   above the innermost `ApiIdHeaderLayer`, so plugins cannot spoof the
   anti-spoof header. `VersionOverrides.plugins` replaces the block
   wholesale like every other override. Considered: pre above the path
   policies (would let plugins see requests the API's own config rejects),
   post below the header transforms (hook rejections would be transformed,
   unlike every other gateway rejection).

7. **Modules load only from the gateway's `plugins_dir`;** definitions
   reference them by relative path. Definition validation checks shape
   (relative, no `..`, no NUL/backslash); the host canonicalizes and
   requires containment (symlink-proof), so admin-API writers cannot make
   the gateway read arbitrary files. Missing or broken modules fail the
   route(-table) build loudly — startup-fatal, but a hot reload keeps the
   previous table serving (ADR-0002 semantics). Modules are recompiled on
   each rebuild (config-time work; a content-keyed compile cache is noted
   future work). Considered: absolute paths in definitions (a config-write
   becomes a file-read primitive), modules inlined base64 in definitions
   (bloats every list/scan; possible future transport for a control
   plane).

8. **`RouteTable::build` now takes a `RouteResources` struct.** The
   plugin loader would have been the eighth positional parameter; the
   progress log had already flagged the refactor. All process-wide,
   reload-surviving resources (forwarder, storage, spike guard, stats,
   metrics, analytics, plugin loader) ride one struct with a
   `new(forwarder, storage)` minimal constructor.

## Consequences

- v1 hooks cannot read or write bodies; a body-capable hook (buffered like
  GraphQL, or a streaming tee like the cache) is its own roadmap decision.
- Short-circuit response bodies are UTF-8 strings in the output JSON;
  binary responses need a base64 flag added to the ABI (compatible: new
  optional field).
- A blocked worker costs at most the plugin's `timeout_ms`; operators
  raising it toward the 1 s cap trade tail latency for plugin budget.
- The response cache sits below the post hook, so plugin-set request
  headers do not vary cache keys — cached APIs whose plugins vary
  responses per header need that documented (docs/plugins.md) until a
  Vary story exists.
- New crate `g2-plugin`; wasmtime compiles only for it and the binary.
  Workspace builds get heavier by one cranelift; the proxy/middleware
  crates' compile times are untouched.
- The ABI is versioned: a future v2 (component model or richer powers)
  can coexist by checking `g2_abi_version` at load.
