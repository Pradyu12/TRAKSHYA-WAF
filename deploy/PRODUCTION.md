# PRODUCTION.md

Production Deployment Guide

1. Clone the proper repo
   git clone https://github.com/Pradyu12/KALKI-WAF.git
   cd KALKI-WAF

2. Install system dependencies
   Ubuntu/Debian:
     apt-get update
     apt-get install -y nginx nodejs npm cargo golang-go cmake build-essential libssl-dev pkg-config

3. Build and deploy
   Option A - Docker:
     docker compose -f docker-compose.stack.yml up -d --build
     Verify: curl -f http://localhost:8000/health

   Option B - Systemd:
     sudo bash deploy/production-setup.sh trakshya trakshya
     sudo systemctl status trakshya-dashboard trakshya-proxy trakshya-api

4. Reverse proxy
   Copy deploy/nginx/trakshya-dashboard.conf to /etc/nginx/sites-available/trakshya-waf
   Symlink to sites-enabled, test config, reload nginx.

5. Firewall
     ufw allow 80/tcp
     ufw allow 443/tcp
     ufw allow 8080/tcp
     ufw enable

6. Environment
     nano /opt/trakshya-waf/.env
   Required variables:
     TRAKSHYA_API_KEY: random strong value
     TRAKSHYA_MGMT_PORT: 8000
     TRAKSHYA_PROXY_PORT: 8080
     TRAKSHYA_FRONTEND_DIR: /opt/trakshya-waf/frontend
     TRAKSHYA_DB_PATH: /opt/trakshya-waf/data/trakshya.db

7. TLS
   Generate certs:
     make certs
   Terminate TLS in nginx/caddy/datadog-agent and forward to dashboard/proxy.

8. Observability
   Optional Datadog agent is included in docker-compose.stack.yml.
   For bare metal/systemd, add systemd journal forwarding or Prometheus scrape configs.

9. Backup
   Backup /opt/trakshya-waf/data and /opt/trakshya-waf/.env regularly.

10. Troubleshooting
    journalctl -u trakshya-dashboard -f
    journalctl -u trakshya-proxy -f
    journalctl -u trakshya-api -f
    curl -f http://localhost:8000/health
    curl -f http://localhost:8080/health
    curl -f http://localhost:8001/health
