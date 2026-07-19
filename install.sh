#!/usr/bin/env bash
set -euo pipefail

if [ -f "$(pwd)/Cargo.toml" ] && [ -d "$(pwd)/rust" ]; then
  REPO_ROOT="$(pwd)"
else
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
fi

if [ -f "$REPO_ROOT/scripts/trakshya-ascii.sh" ]; then
  bash "$REPO_ROOT/scripts/trakshya-ascii.sh" || true
fi

INSTALL_DIR="$HOME/.local/bin"
BIN_NAME="trakshya-waf"
DASHBOARD_PORT="${TRAKSHYA_DASHBOARD_PORT:-8000}"
PROXY_PORT="${TRAKSHYA_PROXY_PORT:-8080}"

echo ""
echo "  TRAKSHYA WAF — Local Setup"
echo ""

mkdir -p "$INSTALL_DIR"

if command -v cargo >/dev/null 2>&1 && [ -d "$REPO_ROOT/rust" ]; then
  echo "  [1/3] Building Rust proxy..."
  (
    cd "$REPO_ROOT/rust"
    cargo build --release 2>&1 | tail -5 || echo "  Rust build failed; will use Node fallback if needed."
  )
else
  echo "  [1/3] Cargo not found; skipping Rust build."
fi

if command -v node >/dev/null 2>&1 && [ -f "$REPO_ROOT/package.json" ]; then
  echo "  [2/3] Installing dashboard dependencies..."
  (cd "$REPO_ROOT" && npm install --no-audit --no-fund) || echo "  npm install failed; dashboard may not start."
else
  echo "  [2/3] Node.js not found; dashboard cannot start."
fi

echo "  [3/3] Installing launcher..."
cat >"$INSTALL_DIR/$BIN_NAME" <<EOF
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$REPO_ROOT"
DASHBOARD_PORT=$DASHBOARD_PORT
PROXY_PORT=$PROXY_PORT
RUST_BIN="\$REPO_ROOT/rust/target/release/trakshya-proxy"

echo "Starting TRAKSHYA WAF..."
cd "\$REPO_ROOT"
[ -f "\$REPO_ROOT/scripts/trakshya-ascii.sh" ] && bash "\$REPO_ROOT/scripts/trakshya-ascii.sh" || true

cleanup() {
  [ -n "\${DASHBOARD_PID:-}" ] && kill "\$DASHBOARD_PID" 2>/dev/null || true
  [ -n "\${PROXY_PID:-}" ] && kill "\$PROXY_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [ -x "\$RUST_BIN" ]; then
  echo "  [proxy] http://localhost:\$PROXY_PORT"
  "\$RUST_BIN" --port "\$PROXY_PORT" &
  PROXY_PID=\$!
fi

if command -v node >/dev/null 2>&1; then
  echo "  [dashboard] http://localhost:\$DASHBOARD_PORT"
  node server.js &
  DASHBOARD_PID=\$!
else
  echo "Node.js not found; cannot start dashboard."
  exit 1
fi

echo "Press Ctrl+C to stop."
wait
EOF
chmod +x "$INSTALL_DIR/$BIN_NAME"

echo ""
echo "  Installed: $INSTALL_DIR/$BIN_NAME"
echo "  Run:      $BIN_NAME"
echo "  Dashboard: http://localhost:$DASHBOARD_PORT"
[ -x "$REPO_ROOT/rust/target/release/trakshya-proxy" ] && echo "  Proxy:     http://localhost:$PROXY_PORT"
echo ""
