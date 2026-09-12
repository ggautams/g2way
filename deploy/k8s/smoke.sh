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

printf '\nSMOKE OK — gateway is proxying end to end and replicas share rate limits.\n'
