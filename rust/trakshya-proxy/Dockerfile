FROM rust:latest AS builder
WORKDIR /app

# Cache layer 1: dependencies (only invalidated by Cargo.toml / Cargo.lock changes)
COPY Cargo.toml Cargo.lock ./
COPY trakshya-proxy/Cargo.toml trakshya-proxy/
COPY trakshya-rules/Cargo.toml trakshya-rules/
COPY trakshya-rate-limiter/Cargo.toml trakshya-rate-limiter/
COPY trakshya-circuit-breaker/Cargo.toml trakshya-circuit-breaker/
COPY trakshya-geoip/Cargo.toml trakshya-geoip/
COPY trakshya-jwt/Cargo.toml trakshya-jwt/

RUN mkdir -p \
    trakshya-proxy/src \
    trakshya-rules/src \
    trakshya-rate-limiter/src \
    trakshya-circuit-breaker/src \
    trakshya-geoip/src \
    trakshya-jwt/src \
    && echo "fn main() {}" > trakshya-proxy/src/main.rs \
    && echo "pub fn placeholder() {}" > trakshya-rules/src/lib.rs \
    && echo "pub fn placeholder() {}" > trakshya-rate-limiter/src/lib.rs \
    && echo "pub fn placeholder() {}" > trakshya-circuit-breaker/src/lib.rs \
    && echo "pub fn placeholder() {}" > trakshya-geoip/src/lib.rs \
    && echo "pub fn placeholder() {}" > trakshya-jwt/src/lib.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p trakshya-proxy

# Cache layer 2: real source (fast rebuild — only crates with changes recompile)
RUN rm -rf trakshya-proxy/src trakshya-rules/src trakshya-rate-limiter/src \
    trakshya-circuit-breaker/src trakshya-geoip/src trakshya-jwt/src

COPY trakshya-proxy/src trakshya-proxy/src
COPY trakshya-rules/src trakshya-rules/src
COPY trakshya-rate-limiter/src trakshya-rate-limiter/src
COPY trakshya-circuit-breaker/src trakshya-circuit-breaker/src
COPY trakshya-geoip/src trakshya-geoip/src
COPY trakshya-jwt/src trakshya-jwt/src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p trakshya-proxy && \
    cp target/release/trakshya-proxy /trakshya-proxy

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libssl3 libstdc++6 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /trakshya-proxy /usr/local/bin/trakshya-proxy
EXPOSE 8080
ENTRYPOINT ["trakshya-proxy"]
CMD ["--port", "8080"]
