FROM golang:1.23-bookworm AS builder
WORKDIR /app
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /trakshya-api ./go/cmd/trakshya-api/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libsqlite3-0 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /trakshya-api /usr/local/bin/trakshya-api
EXPOSE 8000
ENTRYPOINT ["trakshya-api"]
CMD ["--port", "8000"]
