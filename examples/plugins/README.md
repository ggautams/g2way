# Example g2way plugins

Guest WASM modules for the gateway's plugin hooks (ABI v1 — the full
contract, semantics and a Rust walkthrough live in
[`docs/plugins.md`](../../docs/plugins.md); design in
[ADR-0005](../../docs/adr/0005-wasm-plugins.md)).

- `header_tag.wat` — the smallest useful plugin: sets `x-from-plugin: yes`
  and strips `x-internal` from every request. Compile it with `wat2wasm`
  (or any WAT assembler) into a directory served via `--plugins-dir`, and
  reference it from a definition's `plugins.pre` list.

The e2e suite (`crates/g2way/tests/plugin_e2e.rs`) compiles and runs
`header_tag.wat` through a real gateway, so the example is kept working by
`make check`.
