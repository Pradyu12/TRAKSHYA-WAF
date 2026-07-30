#!/usr/bin/env bash
set -euo pipefail

# Colors
PINK='\033[0;35m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

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
echo -e "  ${BOLD}${PINK}TRAKSHYA WAF${RESET} — Local Setup (DuckDB + live API)"
echo ""

mkdir -p "$INSTALL_DIR"
mkdir -p "$REPO_ROOT/bin"

# ---- Step 1: Build Rust proxy (with timeout to avoid hanging) ----
if command -v cargo >/dev/null 2>&1 && [ -d "$REPO_ROOT/rust" ]; then
  echo -e "  ${CYAN}◆${RESET} [1/3] Building Rust proxy..."
  echo -e "  ${CYAN}◇${RESET} This may take a few minutes on first build (cargo fetches & compiles deps)."
  (
    cd "$REPO_ROOT/rust"
    # Use timeout on Linux/macOS; fallback to background with wait on Windows
    if command -v timeout >/dev/null 2>&1; then
      timeout 600 cargo build --release 2>&1 | tail -8
    else
      # Windows fallback: run in background with max 10 min wait
      cargo build --release &
      BUILD_PID=$!
      # Spin indicator
      SPIN=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
      i=0
      while kill -0 $BUILD_PID 2>/dev/null; do
        printf "\r  ${CYAN}⏳${RESET} Building... ${SPIN[$i]} "
        i=$(( (i + 1) % 8 ))
        sleep 1
      done
      printf "\r  ${GREEN}✓${RESET} Build complete.          \n"
      wait $BUILD_PID
    fi
  ) && echo -e "  ${GREEN}✓${RESET} Rust proxy built successfully." || echo -e "  ${YELLOW}⚠${RESET} Rust build had issues; proxy may be unavailable. Run 'cargo build --release' in rust/ to debug."
  echo ""
else
  echo -e "  ${YELLOW}⚠${RESET} [1/3] Cargo not found or rust/ dir missing; skipping Rust proxy build."
  echo ""
fi

# ---- Step 2: Build Go API ----
if ! command -v gcc >/dev/null 2>&1; then
  echo -e "  ${YELLOW}⚠${RESET} GCC (C compiler) is required for Go DuckDB (CGO)."
  echo -e "  ${CYAN}◇${RESET} Install it via:"
  echo -e "  ${CYAN}◇${RESET}   Linux:  sudo apt install gcc"
  echo -e "  ${CYAN}◇${RESET}   macOS:  xcode-select --install"
  echo -e "  ${CYAN}◇${RESET}   Windows (MSYS2): pacman -S mingw-w64-x86_64-gcc"
  echo ""
fi

if command -v go >/dev/null 2>&1 && [ -d "$REPO_ROOT/go" ]; then
  echo -e "  ${CYAN}◆${RESET} [2/3] Building Go management API (DuckDB)..."
  (
    cd "$REPO_ROOT/go"
    CGO_ENABLED=1 go build -o "$REPO_ROOT/bin/trakshya-api" ./cmd/trakshya-api/
  ) && echo -e "  ${GREEN}✓${RESET} Go API built successfully." || {
    echo -e "  ${RED}✗${RESET} Go build failed."
    exit 1
  }
  echo ""
else
  echo -e "  ${RED}✗${RESET} [2/3] Go not found; cannot build live API."
  echo -e "  ${CYAN}◇${RESET} Install Go: https://go.dev/dl/"
  exit 1
fi

# ---- Step 3: Install launcher ----
echo -e "  ${CYAN}◆${RESET} [3/3] Installing launcher..."

cat >"$INSTALL_DIR/$BIN_NAME" <<LAUNCHER
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$REPO_ROOT"
DASHBOARD_PORT=$DASHBOARD_PORT
PROXY_PORT=$PROXY_PORT
RUST_BIN="\$REPO_ROOT/rust/target/release/trakshya-proxy"
API_BIN="\$REPO_ROOT/bin/trakshya-api"

echo ""
echo -e "  \033[1;35mTRAKSHYA WAF\033[0m — Starting..."
echo ""

cd "\$REPO_ROOT"
[ -f "\$REPO_ROOT/scripts/trakshya-ascii.sh" ] && bash "\$REPO_ROOT/scripts/trakshya-ascii.sh" || true

cleanup() {
  echo ""
  echo "  Shutting down..."
  [ -n "\${API_PID:-}" ] && kill "\$API_PID" 2>/dev/null || true
  [ -n "\${PROXY_PID:-}" ] && kill "\$PROXY_PID" 2>/dev/null || true
  echo "  Stopped."
}
trap cleanup EXIT

export TRAKSHYA_MGMT_PORT="\$DASHBOARD_PORT"
export TRAKSHYA_DUCKDB_PATH="\${TRAKSHYA_DUCKDB_PATH:-\$REPO_ROOT/trakshya_events.duckdb}"
export TRAKSHYA_FRONTEND_DIR="\$REPO_ROOT/frontend"

if [ ! -x "\$API_BIN" ]; then
  echo "  API binary missing: \$API_BIN (re-run install.sh)"
  exit 1
fi

echo -e "  \033[0;36m◆\033[0m Dashboard + API → http://localhost:\$DASHBOARD_PORT"
"\$API_BIN" &
API_PID=\$!

if [ -x "\$RUST_BIN" ]; then
  echo -e "  \033[0;36m◆\033[0m Proxy           → http://localhost:\$PROXY_PORT"
  "\$RUST_BIN" --port "\$PROXY_PORT" &
  PROXY_PID=\$!
fi

echo ""
echo "  Press Ctrl+C to stop."
wait
LAUNCHER
chmod +x "$INSTALL_DIR/$BIN_NAME"

echo -e "  ${GREEN}✓${RESET} Launcher installed to ${INSTALL_DIR}/${BIN_NAME}"
echo ""
echo -e "  ┌────────────────────────────────────────────┐"
echo -e "  │  ${BOLD}Done!${RESET} Run:  ${CYAN}${BIN_NAME}${RESET}                          │"
echo -e "  │  ${BOLD}Open:${RESET}    ${CYAN}http://localhost:${DASHBOARD_PORT}${RESET}             │"
if [ -x "$REPO_ROOT/rust/target/release/trakshya-proxy" ]; then
  echo -e "  │  ${BOLD}Proxy:${RESET}   ${CYAN}http://localhost:${PROXY_PORT}${RESET}             │"
fi
echo -e "  └────────────────────────────────────────────┘"
echo ""
