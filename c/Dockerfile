FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y build-essential cmake pkg-config libmicrohttpd-dev libcurl4-openssl-dev libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libmicrohttpd12 libcurl4 openssl iptables && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/build/kalki-systemd /usr/local/bin/
EXPOSE 9001
CMD ["kalki-systemd"]
