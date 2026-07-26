# PRODUCTION.md

Production Deployment Guide

1. Clone the repo
   ```bash
   git clone https://github.com/Pradyu12/TRAKSHYA-WAF.git
   cd TRAKSHYA-WAF
   ```

2. Install system dependencies
   Ubuntu/Debian:
     ```bash
     apt-get update
     apt-get install -y nginx cargo golang-go cmake build-essential libssl-dev pkg-config
     ```

3. Build and deploy
   Option A - Docker (DuckDB volume):
     ```bash
     docker compose up -d --build
     curl -f http://localhost:8000/ready
     ```

   Option B - Systemd:
     ```bash
     sudo bash deploy/production-setup.sh trakshya trakshya
     sudo systemctl status trakshya-proxy trakshya-api
     ```

   Option C - Kubernetes (recommended):
     ```bash
     kubectl apply -f k8s/
     # or
     helm install trakshya-waf ./helm/trakshya-waf \
       --namespace trakshya-waf --create-namespace \
       --set secrets.apiKey=$(openssl rand -hex 32)
     ```

4. Reverse proxy
   Copy `deploy/nginx/trakshya-dashboard.conf` to `/etc/nginx/sites-available/trakshya-waf`
   Point all `/api` traffic to the Go management API (`:8000`). Do not use the removed Node mock server.

5. Firewall
     ```bash
     ufw allow 80/tcp
     ufw allow 443/tcp
     ufw allow 8080/tcp
     ufw enable
     ```

6. Environment
     ```bash
     nano /opt/trakshya-waf/.env
     ```
   Required variables:
     - `TRAKSHYA_API_KEY`: random strong value
     - `TRAKSHYA_MGMT_PORT`: `8000`
     - `TRAKSHYA_PROXY_PORT`: `8080`
     - `TRAKSHYA_FRONTEND_DIR`: `/opt/trakshya-waf/frontend`
     - `TRAKSHYA_DUCKDB_PATH`: `/opt/trakshya-waf/data/trakshya_events.duckdb`

7. TLS
   Generate certs with `make certs`. Terminate TLS in nginx/caddy and forward to API/proxy.

8. Observability
   Prometheus scrape `/api/metrics` on the API. Optional OTLP via `OTLP_ENDPOINT`.
   No Datadog, n8n, or Firebase integrations.

9. Backup
   Backup the DuckDB file (`TRAKSHYA_DUCKDB_PATH`) and `.env` regularly.

10. Troubleshooting
    ```bash
    journalctl -u trakshya-proxy -f
    journalctl -u trakshya-api -f
    curl -f http://localhost:8000/health
    curl -f http://localhost:8000/ready
    curl -f http://localhost:8080/health
    ```

11. Kubernetes updates
    Rebuild/push images, then roll deployments:
    ```bash
    kubectl set image deployment/trakshya-api api=ghcr.io/Pradyu12/trakshya-waf-api:newtag -n trakshya-waf
    kubectl set image deployment/trakshya-proxy proxy=ghcr.io/Pradyu12/trakshya-waf-proxy:newtag -n trakshya-waf
    kubectl rollout status deployment/trakshya-api -n trakshya-waf
    ```
