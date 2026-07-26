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
echo "  TRAKSHYA WAF — Local Setup (DuckDB + live API)"
echo ""

mkdir -p "$INSTALL_DIR"

if command -v cargo >/dev/null 2>&1 && [ -d "$REPO_ROOT/rust" ]; then
  echo "  [1/3] Building Rust proxy..."
  (
    cd "$REPO_ROOT/rust"
    cargo build --release 2>&1 | tail -5 || echo "  Rust build failed; proxy may be unavailable."
  )
else
  echo "  [1/3] Cargo not found; skipping Rust build."
fi

if command -v go >/dev/null 2>&1 && [ -d "$REPO_ROOT/go" ]; then
  echo "  [2/3] Building Go management API (DuckDB)..."
  (
    cd "$REPO_ROOT/go"
    CGO_ENABLED=1 go build -o "$REPO_ROOT/bin/trakshya-api" ./cmd/trakshya-api/
  )
else
  echo "  [2/3] Go not found; cannot build live API."
  exit 1
fi

echo "  [3/3] Installing launcher..."
mkdir -p "$REPO_ROOT/bin"
cat >"$INSTALL_DIR/$BIN_NAME" <<EOF
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$REPO_ROOT"
DASHBOARD_PORT=$DASHBOARD_PORT
PROXY_PORT=$PROXY_PORT
RUST_BIN="\$REPO_ROOT/rust/target/release/trakshya-proxy"
API_BIN="\$REPO_ROOT/bin/trakshya-api"

echo "Starting TRAKSHYA WAF (live DuckDB)..."
cd "\$REPO_ROOT"
[ -f "\$REPO_ROOT/scripts/trakshya-ascii.sh" ] && bash "\$REPO_ROOT/scripts/trakshya-ascii.sh" || true

cleanup() {
  [ -n "\${API_PID:-}" ] && kill "\$API_PID" 2>/dev/null || true
  [ -n "\${PROXY_PID:-}" ] && kill "\$PROXY_PID" 2>/dev/null || true
}
trap cleanup EXIT

export TRAKSHYA_MGMT_PORT="\$DASHBOARD_PORT"
export TRAKSHYA_DUCKDB_PATH="\${TRAKSHYA_DUCKDB_PATH:-\$REPO_ROOT/trakshya_events.duckdb}"
export TRAKSHYA_FRONTEND_DIR="\$REPO_ROOT/frontend"

if [ ! -x "\$API_BIN" ]; then
  echo "API binary missing: \$API_BIN (re-run install.sh)"
  exit 1
fi

echo "  [api/dashboard] http://localhost:\$DASHBOARD_PORT"
"\$API_BIN" &
API_PID=\$!

if [ -x "\$RUST_BIN" ]; then
  echo "  [proxy] http://localhost:\$PROXY_PORT"
  "\$RUST_BIN" --port "\$PROXY_PORT" &
  PROXY_PID=\$!
fi

echo "Press Ctrl+C to stop."
wait
EOF
chmod +x "$INSTALL_DIR/$BIN_NAME"

echo ""
echo "  Installed: $INSTALL_DIR/$BIN_NAME"
echo "  Run:      $BIN_NAME"
echo "  Dashboard: http://localhost:$DASHBOARD_PORT (live DuckDB API)"
[ -x "$REPO_ROOT/rust/target/release/trakshya-proxy" ] && echo "  Proxy:     http://localhost:$PROXY_PORT"
echo ""
