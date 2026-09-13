#!/usr/bin/env bash
# End-to-end smoke test for a deployed g2way cluster (minikube or any k8s).
# Usage: deploy/k8s/smoke.sh   (or `make smoke`)
set -euo pipefail

NS=g2way
LOCAL_PORT="${LOCAL_PORT:-18080}"
POD_A_PORT="${POD_A_PORT:-18081}"
POD_B_PORT="${POD_B_PORT:-18082}"
ADMIN_PORT="${ADMIN_PORT:-19696}"
# Must match G2_ADMIN_SECRET in gateway.yaml (dev/minikube-only).
ADMIN_SECRET="${ADMIN_SECRET:-g2-smoke-admin-secret}"

say() { printf '\n== %s\n' "$*"; }
fail() { printf 'SMOKE FAILED: %s\n' "$*" >&2; exit 1; }

PF_PIDS=()
cleanup() {
  for pid in "${PF_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

# Poll a URL until it answers (any HTTP status) or time out.
wait_for() {
  local url=$1
  for _ in $(seq 1 20); do
    curl -s -o /dev/null "$url" 2>/dev/null && return 0
    sleep 0.5
  done
  fail "timed out waiting for $url"
}

say "waiting for deployments to be ready"
kubectl -n "$NS" rollout status deploy/redis --timeout=120s
kubectl -n "$NS" rollout status deploy/httpbin --timeout=120s
kubectl -n "$NS" rollout status deploy/otel-collector --timeout=120s
kubectl -n "$NS" rollout status deploy/g2way --timeout=120s

say "port-forwarding service/g2way to localhost:$LOCAL_PORT"
kubectl -n "$NS" port-forward service/g2way "$LOCAL_PORT:8080" >/dev/null 2>&1 &
PF_PIDS+=($!)
wait_for "http://localhost:$LOCAL_PORT/hello"

say "checking /hello"
curl -sf "http://localhost:$LOCAL_PORT/hello" | grep -q '"status":"pass"' \
  || fail "/hello did not report status pass"

say "proxying through the gateway to httpbin"
BODY=$(curl -sf "http://localhost:$LOCAL_PORT/httpbin/get?smoke=1")
# go-httpbin echoes the upstream URL it saw; query args render as scalars or
# arrays depending on version, so assert on the URL instead.
echo "$BODY" | grep -q 'get?smoke=1' || fail "query param did not reach upstream"
echo "$BODY" | grep -q '"X-Forwarded-For"' || fail "X-Forwarded-For missing upstream"

say "checking 404 for unrouted path"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$LOCAL_PORT/unrouted")
[ "$CODE" = "404" ] || fail "expected 404 for unrouted path, got $CODE"

say "checking both replicas are serving"
READY=$(kubectl -n "$NS" get deploy g2way -o jsonpath='{.status.readyReplicas}')
[ "$READY" = "2" ] || fail "expected 2 ready replicas, got ${READY:-0}"

# --- Multi-pod rate-limit correctness ------------------------------------
# Two replicas must share one sliding-window counter via Redis. We forward
# each pod individually (a Service port-forward pins to a single pod) and
# alternate requests between them: with a limit of 5, request 6 must be 429
# even though each pod saw only 3 requests. Per-pod counters would allow it.

say "port-forwarding both gateway pods individually"
PODS=($(kubectl -n "$NS" get pods -l app=g2way \
  --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'))
[ "${#PODS[@]}" = "2" ] || fail "expected 2 running gateway pods, got ${#PODS[@]}"
kubectl -n "$NS" port-forward "pod/${PODS[0]}" \
  "$POD_A_PORT:8080" "$ADMIN_PORT:9696" >/dev/null 2>&1 &
PF_PIDS+=($!)
kubectl -n "$NS" port-forward "pod/${PODS[1]}" "$POD_B_PORT:8080" >/dev/null 2>&1 &
PF_PIDS+=($!)
wait_for "http://localhost:$POD_A_PORT/hello"
wait_for "http://localhost:$POD_B_PORT/hello"
wait_for "http://localhost:$ADMIN_PORT/g2/health"

say "checking /limited/ requires a token"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$POD_A_PORT/limited/get")
[ "$CODE" = "401" ] || fail "expected 401 without token on /limited/, got $CODE"

say "provisioning a rate-limited key via the admin API"
# Unique per run so a lingering sliding window from a previous run can't
# skew the counts. PUT lets us choose the raw key (no jq dependency).
KEY="smoke-$(date +%s)-$RANDOM"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "X-G2-Authorization: $ADMIN_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"alias":"smoke","rate":{"requests":5,"per_seconds":60},"access":{"httpbin-limited":{}}}' \
  "http://localhost:$ADMIN_PORT/g2/keys/$KEY")
[ "$CODE" = "200" ] || fail "admin key PUT returned $CODE (is Redis wired up?)"

say "alternating 6 requests across the two pods (limit is 5/60s)"
for i in 1 2 3 4 5; do
  if [ $((i % 2)) = 1 ]; then PORT=$POD_A_PORT; else PORT=$POD_B_PORT; fi
  CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $KEY" "http://localhost:$PORT/limited/get")
  [ "$CODE" = "200" ] || fail "request $i expected 200, got $CODE"
done
HEADERS=$(curl -s -D - -o /dev/null -w 'HTTP_CODE:%{http_code}' \
  -H "Authorization: Bearer $KEY" "http://localhost:$POD_B_PORT/limited/get")
echo "$HEADERS" | grep -q 'HTTP_CODE:429' \
  || fail "request 6 should be 429 — counters are not shared across pods"
echo "$HEADERS" | grep -qi '^x-ratelimit-limit: 5' || fail "x-ratelimit-limit missing/wrong"
echo "$HEADERS" | grep -qi '^x-ratelimit-remaining: 0' || fail "x-ratelimit-remaining missing/wrong"
echo "$HEADERS" | grep -qi '^x-ratelimit-reset:' || fail "x-ratelimit-reset missing"
echo "$HEADERS" | grep -qi '^retry-after:' || fail "retry-after missing"

say "deleting the smoke key"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
  -H "X-G2-Authorization: $ADMIN_SECRET" \
  "http://localhost:$ADMIN_PORT/g2/keys/$KEY")
[ "$CODE" = "200" ] || fail "admin key DELETE returned $CODE"

# --- Dashboard & Prometheus (pod A's admin listener) ----------------------

say "checking the dashboard endpoints"
NODE=$(curl -sf -H "X-G2-Authorization: $ADMIN_SECRET" \
  "http://localhost:$ADMIN_PORT/g2/node")
echo "$NODE" | grep -q '"httpbin-limited"' \
  || fail "/g2/node does not list the httpbin-limited API"
STATS=$(curl -sf -H "X-G2-Authorization: $ADMIN_SECRET" \
  "http://localhost:$ADMIN_PORT/g2/stats")
# Pod A served at least the tokenless 401 and rate-limit requests 1/3/5.
echo "$STATS" | grep -q '"httpbin-limited"' \
  || fail "/g2/stats has no counters for httpbin-limited"

say "checking the Prometheus endpoint (no admin secret)"
curl -sf "http://localhost:$ADMIN_PORT/metrics" \
  | grep -q 'http_server_request_duration_seconds' \
  || fail "/metrics is missing the request-duration histogram"

# --- Hot reload -----------------------------------------------------------
# A definition created via the admin API must go live on BOTH pods after a
# single POST /g2/reload (Redis pub/sub fan-out), with no restarts. The
# listen path is unique per run so a leftover def from a failed prior run
# can't satisfy the pre-reload 404 check; the fixed api_id means PUT simply
# overwrites such a leftover.

say "creating an API definition via the admin API"
RELOAD_PATH="/reload-smoke-$RANDOM/"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "X-G2-Authorization: $ADMIN_SECRET" \
  -H 'Content-Type: application/json' \
  -d "{\"api_id\":\"smoke-reload\",\"name\":\"reload smoke\",
       \"listen_path\":\"$RELOAD_PATH\",
       \"target_url\":\"http://httpbin.g2way.svc.cluster.local:8080\",
       \"auth\":{\"mode\":\"keyless\"}}" \
  "http://localhost:$ADMIN_PORT/g2/apis/smoke-reload")
[ "$CODE" = "200" ] || fail "admin API def PUT returned $CODE"
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  "http://localhost:$POD_A_PORT${RELOAD_PATH}get")
[ "$CODE" = "404" ] || fail "expected 404 before reload, got $CODE"

say "broadcasting /g2/reload and waiting for both pods"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "X-G2-Authorization: $ADMIN_SECRET" "http://localhost:$ADMIN_PORT/g2/reload")
[ "$CODE" = "200" ] || fail "POST /g2/reload returned $CODE"
both_pods_return() {
  local want=$1 code
  for port in "$POD_A_PORT" "$POD_B_PORT"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' \
      "http://localhost:$port${RELOAD_PATH}get")
    [ "$code" = "$want" ] || return 1
  done
}
reload_settled() {
  for _ in $(seq 1 30); do
    both_pods_return "$1" && return 0
    sleep 0.5
  done
  return 1
}
reload_settled 200 || fail "reloaded API is not serving on both pods"

say "deleting the definition and reloading again"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
  -H "X-G2-Authorization: $ADMIN_SECRET" \
  "http://localhost:$ADMIN_PORT/g2/apis/smoke-reload")
[ "$CODE" = "200" ] || fail "admin API def DELETE returned $CODE"
curl -s -o /dev/null -X POST \
  -H "X-G2-Authorization: $ADMIN_SECRET" "http://localhost:$ADMIN_PORT/g2/reload"
reload_settled 404 || fail "deleted API is still routed after reload"

# --- Telemetry reaches the collector --------------------------------------
# The debug exporter logs one summary line per batch; the gateway's batch
# span processor flushes every ~5s, so poll for a bit.

say "checking the otel-collector received traces"
TRACES_OK=
for _ in $(seq 1 30); do
  if kubectl -n "$NS" logs deploy/otel-collector --since=10m 2>/dev/null \
    | grep -qiE 'TracesExporter|resource spans'; then
    TRACES_OK=1
    break
  fi
  sleep 1
done
[ -n "$TRACES_OK" ] || fail "otel-collector logs show no trace batches"

printf '\nSMOKE OK — proxying, shared rate limits, dashboard, hot reload, and telemetry all verified.\n'
