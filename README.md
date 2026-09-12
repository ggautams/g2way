# g2way

A full-featured API gateway written in Rust.
Built for horizontal scaling in Kubernetes: stateless gateway pods, shared
state in Redis (from M2), OpenTelemetry observability (from M5).

Status: **M1** — core reverse proxy (see `ROADMAP.md` for the full plan and
current progress; `docs/adr/` for architecture decisions).

## Quick start (local)

```sh
make httpbin-up   # local upstream on :8000 (docker)
make run          # gateway on :8080, APIs from examples/apis/
curl localhost:8080/hello
curl localhost:8080/httpbin/get
```

## Quick start (minikube)

```sh
minikube start                # if not already running
make minikube-load            # build g2way:dev and load it into the cluster
make k8s-deploy               # namespace g2way: gateway ×2 + go-httpbin
make smoke                    # port-forward + end-to-end checks
```

## Configuring APIs

Drop one JSON or YAML file per API into the apps directory (`--apps-dir`,
default `./apps`). Minimal example:

```json
{
  "api_id": "httpbin",
  "name": "Httpbin passthrough",
  "listen_path": "/httpbin/",
  "target_url": "http://localhost:8000"
}
```

Optional fields: `strip_listen_path` (default `true`),
`preserve_host_header` (default `false`), `upstream_timeout_ms`
(default `30000`), `active` (default `true`).

## Workspace layout

| Crate | Role |
|---|---|
| `g2-core` | Domain types: API definitions, gateway config, loader |
| `g2-storage` | `Storage` trait; in-memory impl (Redis from M2) |
| `g2-proxy` | Router, request rewriting, upstream forwarding |
| `g2-middleware` | Per-API tower layers (auth, limits — from M2) |
| `g2-admin` | Admin/control API (from M2) |
| `g2-telemetry` | Logging now; OTLP + analytics from M5 |
| `g2way` | The binary |

## Development

`make check` is the gate: rustfmt, clippy (`-D warnings`), all tests, and
rustdoc (`-D warnings`) must pass before every commit. Plain `cargo test`
needs no external services.
