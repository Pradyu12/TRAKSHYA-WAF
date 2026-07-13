FROM rust:latest AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY kalki-proxy kalki-proxy/
COPY kalki-rules kalki-rules/
COPY kalki-rate-limiter kalki-rate-limiter/
COPY kalki-circuit-breaker kalki-circuit-breaker/
COPY kalki-geoip kalki-geoip/
COPY kalki-jwt kalki-jwt/
RUN cargo build --release -p kalki-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/kalki-proxy /usr/local/bin/
EXPOSE 8080
CMD ["kalki-proxy"]
