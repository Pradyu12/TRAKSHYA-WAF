FROM rust:1.75-bookworm AS builder
WORKDIR /app
COPY rust/Cargo.toml rust/Cargo.lock ./
RUN mkdir -p krsna-proxy/src && touch krsna-proxy/src/lib.rs && cargo build --release -p krsna-proxy || true
COPY . .
RUN cargo build --release -p krsna-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/rust/target/release/trakshya-proxy /usr/local/bin/trakshya-proxy
EXPOSE 8080
ENTRYPOINT ["trakshya-proxy"]
CMD ["--port", "8080"]
