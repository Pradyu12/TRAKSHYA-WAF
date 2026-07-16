#!/usr/bin/env bash
set -euo pipefail

# Determine repo root: prefer current directory if it looks like the repo, else fallback to script location
if [ -f "$(pwd)/Cargo.toml" ] && [ -d "$(pwd)/rust" ]; then
  REPO_ROOT="$(pwd)"
else
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
fi

TRAKSHYA_ASCII="$(cd "$REPO_ROOT/scripts" && bash ./trakshya-ascii.sh 2>/dev/null || true)"
if [ -n "$TRAKSHYA_ASCII" ]; then
  printf '%s\n' "$TRAKSHYA_ASCII"
fi

INSTALL_DIR="$HOME/.local/bin"
BIN_NAME="trakshya-waf"
RUST_BIN="$REPO_ROOT/rust/target/release/trakshya-proxy"
DASHBOARD_PORT=8000
PROXY_PORT=8080

echo -e "\n  \033[1m\033[35mTRAKSHYA WAF\033[0m — Local Setup\n"

mkdir -p "$INSTALL_DIR"

# Build Rust proxy if available
if command -v cargo >/dev/null 2>&1 && [ -d "$REPO_ROOT/rust" ]; then
  echo "  \033[36m●\033[0m Building Rust proxy..."
  pushd "$REPO_ROOT/rust" >/dev/null
  cargo build --release 2>&1 | tail -5 || echo "  \033[33m⚠ Rust build failed, will use mock server.\033[0m"
  popd >/dev/null
else
  echo "  \033[33m⚠ Cargo not found or rust/ missing. Using Node.js mock server instead.\033[0m"
fi

# Create launcher script
cat > "$INSTALL_DIR/$BIN_NAME" <<EOF
#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "\$0")/..")" >/dev/null 2>&1 && pwd || echo "$HOME/.local"
INSTALL_DIR="\$HOME/.local/bin"
BIN_NAME="trakshya-waf"
RUST_BIN="\$REPO_ROOT/rust/target/release/trakshya-proxy"
DASHBOARD_PORT=8000
PROXY_PORT=8080

echo "Starting TRAKSHYA WAF..."
cd "$REPO_ROOT"

if [ -f "$REPO_ROOT/scripts/trakshya-ascii.sh" ]; then
  bash "$REPO_ROOT/scripts/trakshya-ascii.sh"
fi

# Start mock/fallback server if Rust binary not available
if [ ! -x "\$RUST_BIN" ]; then
  if command -v node >/dev/null 2>&1; then
    node server.js &
    SERVER_PID=\$!
  else
    echo "Node.js not found. Please install Node.js 18+ to run the mock server."
    exit 1
  fi
else
  "\$RUST_BIN" --port "\$PROXY_PORT" &
  SERVER_PID=\$!
fi

echo "Dashboard: http://localhost:\$DASHBOARD_PORT"
echo "Press Ctrl+C to stop"

trap "kill \$SERVER_PID 2>/dev/null || true" EXIT
wait \$SERVER_PID
EOF

chmod +x "$INSTALL_DIR/$BIN_NAME"

echo -e "\n  \033[32m✔ Installed successfully!\033[0m\n"
echo "  Binary:  $INSTALL_DIR/$BIN_NAME"
echo "  Run:     $BIN_NAME"
echo "  Or:      npx $BIN_NAME"
echo -e "\n  Dashboard will be available at: http://localhost:$DASHBOARD_PORT\n"
