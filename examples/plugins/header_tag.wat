;; Minimal g2way plugin (ABI v1, see docs/plugins.md): ignores its input
;; and tells the gateway to continue after setting `x-from-plugin: yes` and
;; removing `x-internal` from the request.
;;
;; Build it into a loadable module with the `wat` tool (cargo install wat):
;;
;;     wat2wasm header_tag.wat -o header_tag.wasm     # or: wat -o ...
;;
;; then reference it from an API definition:
;;
;;     "plugins": { "pre": [{ "name": "header-tag", "path": "header_tag.wasm" }] }
;;
;; Layout: the static output document lives at offset 0; g2_alloc hands the
;; host scratch space at 64 KiB (page 2), far above it. Real plugins parse
;; the input JSON the host writes there — see docs/plugins.md for the Rust
;; walkthrough.
(module
  (memory (export "memory") 4)

  ;; The ABI handshake: this module speaks version 1.
  (func (export "g2_abi_version") (result i32) i32.const 1)

  ;; Where the host may write the input document. A fresh instance serves
  ;; every invocation, so a constant bump allocation is enough here.
  (func (export "g2_alloc") (param i32) (result i32) i32.const 65536)

  ;; The output document, returned verbatim by g2_hook.
  (data (i32.const 0) "{\"action\":\"continue\",\"set_headers\":[[\"x-from-plugin\",\"yes\"]],\"remove_headers\":[\"x-internal\"]}")

  ;; Packed return: pointer (0) in the high 32 bits, length in the low 32.
  (func (export "g2_hook") (param i32 i32) (result i64)
    i64.const 93))
