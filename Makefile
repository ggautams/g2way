# g2way developer entry points. `make check` is the gate every change must pass.

.PHONY: check fmt fmt-check clippy test doc build run \
        docker-build minikube-load k8s-deploy k8s-delete smoke \
        httpbin-up httpbin-down redis-up redis-down

## Quality gate: run before every commit. Must stay green.
check: fmt-check clippy test doc

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

build:
	cargo build --workspace --release

## Run the gateway locally against examples/apis (pair with `make httpbin-up`).
run:
	cargo run -p g2way -- --apps-dir examples/apis --log-format pretty

## ---- Local docker helpers ----------------------------------------------

## Local upstream for examples/apis/httpbin.json.
httpbin-up:
	docker run -d --name g2way-httpbin -p 8000:8080 ghcr.io/mccutchen/go-httpbin:v2.15.0

httpbin-down:
	docker rm -f g2way-httpbin

## Redis for storage-backed features and their integration tests (from M2).
redis-up:
	@docker start g2way-redis 2>/dev/null \
		|| docker run -d --name g2way-redis -p 6379:6379 redis:7-alpine

redis-down:
	docker rm -f g2way-redis

## ---- Kubernetes (local minikube) ----------------------------------------

docker-build:
	docker build -f deploy/docker/Dockerfile -t g2way:dev .

## Build the image and make it visible inside the minikube cluster.
## Goes through `docker save`: loading straight from the daemon fails with
## "blob not found" on Docker Desktop's containerd image store.
minikube-load: docker-build
	docker save g2way:dev -o /tmp/g2way-dev.tar
	minikube image load --overwrite /tmp/g2way-dev.tar
	rm -f /tmp/g2way-dev.tar

k8s-deploy:
	kubectl apply -f deploy/k8s/

k8s-delete:
	kubectl delete -f deploy/k8s/ --ignore-not-found

## End-to-end smoke test against the deployed cluster.
smoke:
	deploy/k8s/smoke.sh
