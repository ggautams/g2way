# Upstream service discovery

An API's upstream addresses can be resolved at runtime from an HTTP+JSON
catalog instead of (only) static configuration:

- **One mechanism, many catalogs.** Each gateway pod polls a configurable
  endpoint and extracts hosts from the JSON response via dotted data paths —
  the shape covers Consul, etcd, Eureka, and any bespoke JSON endpoint
  (see ADR-0006 for what was considered and dropped).
- **Swaps are live.** A poll that resolves a different address list replaces
  the API's load-balancing rotation immediately — no `/g2/reload`, no
  restart, no route-table rebuild.
- **Static targets remain the seed and the fallback.** `target_url` (and
  `target_list`, when set) serve traffic until the first successful poll,
  and a failing endpoint never takes targets away (below).

## Configuration

```json
{
  "api_id": "users",
  "name": "Users",
  "listen_path": "/users/",
  "target_url": "http://users-fallback.internal:8000",
  "auth": {"mode": "keyless"},
  "service_discovery": {
    "endpoint": "http://consul.internal:8500/v1/catalog/service/users",
    "parent_data_path": "",
    "data_path": "ServiceAddress",
    "port_data_path": "ServicePort",
    "scheme": "http",
    "interval_ms": 10000,
    "timeout_ms": 5000
  }
}
```

| field | default | meaning |
|---|---|---|
| `endpoint` | required | Absolute `http(s)` URL polled for addresses |
| `data_path` | `""` | Dotted path to the host entry/entries; empty = the value itself |
| `port_data_path` | unset | Dotted path to the port (integer `1`–`65535` or digit string) |
| `parent_data_path` | unset | Dotted path to an array to iterate; per element, the two paths above resolve relative to the element. Empty string = the response root is the array |
| `scheme` | `"http"` | Scheme for bare `host[:port]` entries (`http`/`https`) |
| `interval_ms` | `10000` | Poll interval per pod (milliseconds) |
| `timeout_ms` | `5000` | Per-poll timeout |

Dotted paths index object keys; a segment that parses as a number indexes an
array element (`data.nodes.0.ip`). Response bodies are capped at 1 MiB.

### What entries can look like

- `"10.0.0.7"` / `"users-2.internal"` — bare host: gets `scheme`, the
  resolved port (if `port_data_path` is set), no base path.
- `"10.0.0.7:8300"` / `"[::1]:8300"` — host with port: the entry's own port
  wins over `port_data_path`.
- `"https://users-2.internal:8443/api"` — full URL: used as-is (own scheme,
  port, and base path; the resolved port is ignored). Non-`http(s)` schemes
  fail the poll.

### Extraction shapes

Without `parent_data_path`, `data_path` resolves from the response root to a
single string or an array of strings, and `port_data_path` resolves from the
root to one port applied to every entry:

```json
{"hosts": ["10.0.0.1", "10.0.0.2"], "port": 8080}
```

With `parent_data_path`, that path must resolve to an array; the other paths
resolve per element (the Consul catalog shape — note `parent_data_path: ""`
because Consul's response root *is* the array):

```json
[
  {"ServiceAddress": "10.0.0.1", "ServicePort": 8300},
  {"ServiceAddress": "10.0.0.2", "ServicePort": 8301}
]
```

### Semantics

- **Stale-on-error, never empty.** Any failed poll — transport error,
  non-2xx, unparseable/oversized body, missing path, invalid entry, or an
  **empty result** — keeps the previously mounted addresses and logs a
  warning. A dead catalog degrades discovery to "frozen", never to "no
  upstreams".
- **Swap only on change.** A poll resolving the same addresses leaves the
  mounted set untouched (health flags are not reset, logs stay quiet).
  Changes log at `info` with old/new counts.
- **Health checking composes.** With `health_check` configured, every
  swapped-in address list starts all-healthy and the prober re-derives its
  probe set on the next tick; failing discovered addresses are evicted from
  the rotation as usual. The circuit breaker is per-route and unaffected.
- **Pod-local.** Each pod polls independently (like health probes); expect
  N pods = N pollers against the catalog. The endpoint is fetched over the
  shared HTTP/1.1 client regardless of the API's `upstream_http2`.
- **Versioning.** `versions.<name>.service_discovery` replaces the block
  wholesale for that version, which then polls its own endpoint; like other
  optional overrides it cannot be *cleared* per version — keep discovery
  off the base if only some versions want it.

## Observability

`GET /g2/node` (admin) reports per API:

- `live_targets` — the addresses actually in rotation (equals the
  configured targets until a poll lands);
- `service_discovery` — `{"endpoint", "last_success_unix_secs",
  "last_error"}`, or `null` when discovery is off. `last_success_unix_secs`
  is `null` until the first successful poll; `last_error` is set while the
  latest poll is failing and cleared by the next success.

## Verification

With a gateway running (`make run`), point an API's `service_discovery` at
any local JSON endpoint, e.g. `python3 -m http.server` serving a
`services.json` of `["127.0.0.1:8080"]`, then edit the file and watch
`live_targets` follow in `/g2/node` within one `interval_ms` — no reload.
The end-to-end tests in `crates/g2way/tests/discovery_e2e.rs` script exactly
this, including the dead-catalog stale behavior.
