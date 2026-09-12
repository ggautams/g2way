#!/usr/bin/env bash
# End-to-end smoke test for a deployed g2way cluster (minikube or any k8s).
# Usage: deploy/k8s/smoke.sh   (or `make smoke`)
set -euo pipefail

NS=g2way
LOCAL_PORT="${LOCAL_PORT:-18080}"

say() { printf '\n== %s\n' "$*"; }
fail() { printf 'SMOKE FAILED: %s\n' "$*" >&2; exit 1; }

say "waiting for deployments to be ready"
kubectl -n "$NS" rollout status deploy/httpbin --timeout=120s
kubectl -n "$NS" rollout status deploy/g2way --timeout=120s

say "port-forwarding service/g2way to localhost:$LOCAL_PORT"
kubectl -n "$NS" port-forward service/g2way "$LOCAL_PORT:8080" >/dev/null 2>&1 &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true' EXIT
# Wait for the forward to come up.
for _ in $(seq 1 20); do
  curl -sf "http://localhost:$LOCAL_PORT/hello" >/dev/null 2>&1 && break
  sleep 0.5
done

say "checking /hello"
curl -sf "http://localhost:$LOCAL_PORT/hello" | grep -q '"status":"pass"' \
  || fail "/hello did not report status pass"

say "proxying through the gateway to httpbin"
BODY=$(curl -sf "http://localhost:$LOCAL_PORT/httpbin/get?smoke=1")
echo "$BODY" | grep -q '"smoke": *"1"' || fail "query param did not reach upstream"
echo "$BODY" | grep -q '"X-Forwarded-For"' || fail "X-Forwarded-For missing upstream"

say "checking 404 for unrouted path"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$LOCAL_PORT/unrouted")
[ "$CODE" = "404" ] || fail "expected 404 for unrouted path, got $CODE"

say "checking both replicas are serving"
READY=$(kubectl -n "$NS" get deploy g2way -o jsonpath='{.status.readyReplicas}')
[ "$READY" = "2" ] || fail "expected 2 ready replicas, got ${READY:-0}"

printf '\nSMOKE OK — gateway is proxying end to end.\n'
