FROM rust:latest AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY trakshya-proxy trakshya-proxy/
COPY trakshya-rules trakshya-rules/
COPY trakshya-rate-limiter trakshya-rate-limiter/
COPY trakshya-circuit-breaker trakshya-circuit-breaker/
COPY trakshya-geoip trakshya-geoip/
COPY trakshya-jwt trakshya-jwt/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p trakshya-proxy && \
    cp target/release/trakshya-proxy /trakshya-proxy

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y ca-certificates curl libssl3 libstdc++6 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /trakshya-proxy /usr/local/bin/trakshya-proxy
EXPOSE 8080
ENTRYPOINT ["trakshya-proxy"]
CMD ["--port", "8080"]
