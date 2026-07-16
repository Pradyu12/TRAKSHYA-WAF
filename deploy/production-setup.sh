#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="/opt/trakshya-waf"
SERVICE_USER="${1:-trakshya}"
BUILD_MODE="${2:-mixed}"

mkdir -p "$INSTALL_DIR"

if [ "$SERVICE_USER" != "root" ]; then
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
fi

echo "Deploying TRAKSHYA WAF to $INSTALL_DIR ..."

cp -a server.js package.json "$INSTALL_DIR/"
cp -a frontend "$INSTALL_DIR/"
cp -a landing "$INSTALL_DIR/"
cp -a config "$INSTALL_DIR/"

if [ "$BUILD_MODE" = "local" ] || [ "$BUILD_MODE" = "mixed" ]; then
  mkdir -p "$INSTALL_DIR/build"
  if command -v cargo >/dev/null 2>&1; then
    pushd "$REPO_ROOT/rust" >/dev/null
    cargo build --release
    popd >/dev/null
    install -m 0755 "$REPO_ROOT/rust/target/release/trakshya-proxy" "$INSTALL_DIR/build/trakshya-proxy"
  fi

  if command -v go >/dev/null 2>&1; then
    pushd "$REPO_ROOT/go" >/dev/null
    CGO_ENABLED=1 go build -o "$INSTALL_DIR/build/trakshya-api" ./cmd/trakshya-api/
    popd >/dev/null
  fi
fi

cat > "$INSTALL_DIR/.env" <<'ENVEOF'
TRAKSHYA_MGMT_PORT=8000
TRAKSHYA_PROXY_PORT=8080
TRAKSHYA_FRONTEND_DIR=/opt/trakshya-waf/frontend
TRAKSHYA_DB_PATH=/opt/trakshya-waf/data/trakshya.db
TRAKSHYA_API_KEY=${TRAKSHYA_API_KEY:-changeme-prod}
RUST_LOG=info
NODE_ENV=production
ENVEOF

if [ -f "$REPO_ROOT/dev-certs/trakshya-ca.crt" ]; then
  mkdir -p "$INSTALL_DIR/dev-certs"
  cp -a "$REPO_ROOT/dev-certs"/* "$INSTALL_DIR/dev-certs/"
fi

install -d -m 0755 "$INSTALL_DIR/data"
install -d -m 0755 "$INSTALL_DIR/logs"

if [ "$SERVICE_USER" != "root" ]; then
  chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
fi

cp "$REPO_ROOT/deploy/systemd/trakshya-dashboard.service" /etc/systemd/system/
cp "$REPO_ROOT/deploy/systemd/trakshya-proxy.service" /etc/systemd/system/
cp "$REPO_ROOT/deploy/systemd/trakshya-api.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable trakshya-dashboard trakshya-proxy trakshya-api
systemctl restart trakshya-dashboard trakshya-proxy trakshya-api

echo ""
echo "Deployment complete."
echo "  Installed dir : $INSTALL_DIR"
echo "  Service user  : $SERVICE_USER"
echo "  Env file      : $INSTALL_DIR/.env"
echo "  Dashboard     : http://localhost:8000"
echo "  Proxy         : http://localhost:8080"
echo "  API           : http://localhost:8001"
echo "  Logs          : journalctl -u trakshya-dashboard -f"
