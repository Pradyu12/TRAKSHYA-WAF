FROM rust:1.83-bookworm AS builder
WORKDIR /app
COPY trakshya-proxy/Cargo.toml ./trakshya-proxy/Cargo.toml
RUN mkdir -p trakshya-proxy/src && touch trakshya-proxy/src/lib.rs && cargo build --release -p trakshya-proxy || true
COPY . .
RUN cargo build --release -p trakshya-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/trakshya-proxy/target/release/trakshya-proxy /usr/local/bin/trakshya-proxy
EXPOSE 8080
ENTRYPOINT ["trakshya-proxy"]
CMD ["--port", "8080"]
