FROM golang:1.23-bookworm AS builder
WORKDIR /app
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/cmd ./cmd
COPY go/internal ./internal
COPY go/pkg ./pkg
RUN CGO_ENABLED=1 go build -o /trakshya-api ./cmd/trakshya-api/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libstdc++6 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /trakshya-api /usr/local/bin/trakshya-api
COPY frontend /opt/trakshya/frontend
ENV TRAKSHYA_FRONTEND_DIR=/opt/trakshya/frontend
ENV TRAKSHYA_DUCKDB_PATH=/data/trakshya_events.duckdb
ENV TRAKSHYA_MGMT_PORT=8000
RUN mkdir -p /data
EXPOSE 8000
VOLUME ["/data"]
ENTRYPOINT ["trakshya-api"]
