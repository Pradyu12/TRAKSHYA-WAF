FROM rust:latest AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY krsna-proxy krsna-proxy/
COPY krsna-rules krsna-rules/
COPY krsna-rate-limiter krsna-rate-limiter/
COPY krsna-circuit-breaker krsna-circuit-breaker/
COPY krsna-geoip krsna-geoip/
COPY krsna-jwt krsna-jwt/
RUN cargo build --release -p krsna-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/krsna-proxy /usr/local/bin/trakshya-proxy
EXPOSE 8080
ENTRYPOINT ["trakshya-proxy"]
CMD ["--port", "8080"]
