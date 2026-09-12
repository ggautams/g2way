# Multi-stage build: compile in the official Rust image, run on distroless.
# Build from the repo root: docker build -f deploy/docker/Dockerfile -t g2way:dev .

FROM rust:1-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p g2way

# distroless/cc carries glibc + libgcc, nothing else (no shell, tiny surface).
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /build/target/release/g2way /usr/local/bin/g2way
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/g2way"]
