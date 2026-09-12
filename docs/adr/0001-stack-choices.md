# ADR-0001: Foundational stack choices

Date: 2026-08-30 · Status: accepted

## Context

g2way is a full-featured API gateway in Rust. Hard requirements: horizontal
scaling across k8s pods under high traffic, unit-tested and documented code,
an admin API rich enough to build a dashboard on later, log/metric export to
Datadog-like backends, and single-org operation with a clean path to
multi-org.

## Decisions

1. **Proxy on hyper 1.x + tower; admin plane on axum.** The hot path uses
   hyper directly (no router-framework overhead); middleware are tower
   `Layer`s, unit-testable via `tower::ServiceExt::oneshot`. axum (which is
   tower-native) serves only the admin API. Considered: Cloudflare Pingora
   (opinionated lifecycle, harder to compose per-API chains),
   axum end-to-end (extractor overhead on the hot path).

2. **Redis for distributed state** — API keys, rate-limit counters, quotas,
   and config-reload pub/sub. All access goes
   through the `Storage` trait in `g2-storage`, with `MemoryStorage` for
   tests/dev, so the backend stays swappable. Considered: Postgres+cache
   (distributed rate limiting gets hard), k8s CRDs (couples to k8s, doesn't
   solve counters).

3. **OpenTelemetry for observability.** OTLP traces/metrics plus structured
   JSON logs on stdout; Datadog/Grafana/Elastic all ingest OTLP through their
   collectors, so one integration covers every vendor. An
   `AnalyticsSink` trait keeps room for a native pump later.

4. **Lock-free hot path.** Per-API pipelines are prebuilt at config-load time
   into an immutable route table held in `ArcSwap`; reload swaps the pointer.
   Requests never take a lock or parse configuration.

5. **Multi-org readiness without multi-org features.** Every persistent
   record and Redis key carries `org_id` (`g2:{org}:{kind}:{id}`), fixed to
   `default` for now.

6. **Workflow.** `Makefile` (`make check` = fmt + clippy `-D warnings` +
   tests + rustdoc `-D warnings`) as the commit gate; `ROADMAP.md` checkboxes
   plus a progress log as the cross-session state; ADRs for decisions.

## Consequences

- HTTPS upstreams need an explicit TLS connector (hyper-rustls), scheduled in
  M7; until then only `http://` targets work at runtime.
- Redis becomes a runtime dependency from M2 onward; unit tests stay
  Redis-free via `MemoryStorage`, integration tests use `make redis-up`.
- hyper/tower gives us composition and control at the cost of writing more
  proxy plumbing ourselves (done in M1).
