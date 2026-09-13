# Observability

How g2way's telemetry is wired, and how to land it in a real backend
(Datadog used as the worked example). The instrumentation itself is
described in the M5 entries of `ROADMAP.md`'s progress log; this page is
about deployment.

## What the gateway emits

| Signal | Transport | Knob |
|---|---|---|
| Traces (one span per proxied request) | OTLP HTTP/protobuf → `{endpoint}/v1/traces` | `otlp_endpoint` / `--otlp-endpoint` / `G2_OTLP_ENDPOINT` |
| Metrics (`http.server.request.duration` histogram) | OTLP push → `{endpoint}/v1/metrics` **and** Prometheus pull on `GET /metrics` | same knob; Prometheus is on iff the admin listener is |
| Analytics records (one JSON record per request) | pluggable sink: `stdout`, `redis`, or `otlp_logs` → `{endpoint}/v1/logs` | `analytics_sink` / `--analytics-sink` / `G2_ANALYTICS_SINK` |

Notes:

- `otlp_endpoint` is the collector **base** URL (e.g.
  `http://otel-collector:4318`); the gateway appends the `/v1/*` paths.
  Transport is OTLP over HTTP/protobuf — point it at a collector's 4318
  port, not the gRPC 4317 one.
- `GET /metrics` is served **unauthenticated** on the admin listener
  (scrapers can't send the `X-G2-Authorization` header); keep the admin
  port cluster-internal. `deploy/k8s/gateway.yaml` carries the
  conventional `prometheus.io/*` pod annotations.
- Spans are info-level tracing events: `RUST_LOG=warn` disables export.

## The k8s collector example

`deploy/k8s/otel-collector.yaml` deploys a single
`opentelemetry-collector-contrib` pod receiving OTLP HTTP on 4318 and
printing everything with the `debug` exporter. The gateway Deployment
points `G2_OTLP_ENDPOINT` at it and ships analytics as OTLP logs, so:

```sh
make minikube-load k8s-deploy smoke   # smoke asserts telemetry arrives
kubectl -n g2way logs deploy/otel-collector | grep -E 'Traces|Metrics|Logs'
```

## Wiring Datadog

Option A — **collector-side Datadog exporter** (what the example is
prepared for). The `datadog` exporter ships only in the `-contrib`
collector distribution, which the example image already uses.

1. Put the API key in a Secret:

   ```sh
   kubectl -n g2way create secret generic datadog --from-literal=api-key=<DD_API_KEY>
   ```

2. In `deploy/k8s/otel-collector.yaml`, uncomment the `datadog:` exporter
   in the ConfigMap (set `api.site` for EU/us3/gov sites) and the
   `DD_API_KEY` env block in the Deployment.

3. Replace `debug` with `datadog` in the `traces`/`metrics`/`logs`
   pipelines (or keep both: `exporters: [debug, datadog]`).

Traces land under APM (service name `g2way`), the request-duration
histogram under Metrics, and analytics records in Log Management with
`api_id`/`org_id`/status attributes to facet on.

Option B — **Datadog Agent OTLP ingest**: if a Datadog Agent already runs
in the cluster (e.g. the Helm chart), enable its OTLP receiver
(`otlp.receiver.protocols.http.endpoint: 0.0.0.0:4318` in the Agent
config) and point `G2_OTLP_ENDPOINT` straight at the Agent — no collector
needed. Note the Agent's OTLP log ingest must be enabled separately
(`otlp_config.logs.enabled`).
