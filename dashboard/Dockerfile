FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY frontend ./frontend
COPY landing ./landing
COPY config ./config
COPY server.js package.json ./
RUN npm install --production
EXPOSE 8000 8443
CMD ["node", "server.js"]
