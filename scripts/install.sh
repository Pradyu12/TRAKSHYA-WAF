#!/usr/bin/env bash
set -euo pipefail

# ── TRAKSHYA WAF — One-line CLI Installer ──────────────────────────
# Installs the TRAKSHYA WAF management API + dashboard
# Builds from source using Cargo + Go (no Docker needed)
# ─────────────────────────────────────────────────────────────────────

REPO="Pradyu12/TRAKSHYA-WAF"
BIN_NAME="trakshya-waf"
INSTALL_DIR="${HOME}/.local/bin"
DATA_DIR="${HOME}/.local/share/trakshya"
DASHBOARD_PORT="${TRAKSHYA_DASHBOARD_PORT:-8000}"
PROXY_PORT="${TRAKSHYA_PROXY_PORT:-8080}"

# Colors
PINK='\033[0;35m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
  echo ""
  echo -e "  ${BOLD}${PINK}  ╔═══════════════════════════════════╗${RESET}"
  echo -e "  ${BOLD}${PINK}  ║       T R A K S H Y A   W A F     ║${RESET}"
  echo -e "  ${BOLD}${PINK}  ║     Web Application Firewall      ║${RESET}"
  echo -e "  ${BOLD}${PINK}  ╚═══════════════════════════════════╝${RESET}"
  echo ""
}

check_dep() {
  local cmd="$1" name="$2" url="$3"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo -e "  ${RED}✗${RESET} ${name} is required."
    echo -e "  ${CYAN}◇${RESET} Install it: ${url}"
    return 1
  fi
  echo -e "  ${GREEN}✓${RESET} ${name} found: $(command -v "$cmd")"
  return 0
}

spinner() {
  local pid=$1 msg="$2"
  local spin=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${CYAN}⏳${RESET} %s ${spin[$i]} " "$msg"
    i=$(( (i + 1) % 8 ))
    sleep 0.3
  done
  printf "\r  ${GREEN}✓${RESET} %s done.           \n" "$msg"
}

# ── Main ────────────────────────────────────────────────────────────

banner

echo -e "  ${CYAN}◆${RESET} Checking system requirements..."
echo ""

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"
echo -e "  ${CYAN}◇${RESET} Platform: ${OS} / ${ARCH}"
echo ""

# Check deps
HAS_GO=true
HAS_CARGO=true
HAS_GCC=true

check_dep "go" "Go" "https://go.dev/dl/" || HAS_GO=false
check_dep "cargo" "Cargo/Rust" "https://rustup.rs/" || HAS_CARGO=false
check_dep "git" "Git" "https://git-scm.com/" || { echo -e "  ${RED}✗${RESET} Git is required to clone the repo."; exit 1; }
check_dep "curl" "curl" "https://curl.se/" || { echo -e "  ${RED}✗${RESET} curl is required."; exit 1; }
check_dep "gcc" "GCC (C compiler)" "https://gcc.gnu.org/" || { echo ""; echo -e "  ${YELLOW}⚠${RESET} GCC is needed for Go DuckDB (CGO)."  ; echo -e "  ${CYAN}◇${RESET} Linux: apt install gcc / yum install gcc"; echo -e "  ${CYAN}◇${RESET} macOS: xcode-select --install"; echo -e "  ${CYAN}◇${RESET} Windows (MSYS2): pacman -S mingw-w64-x86_64-gcc"; HAS_GCC=false; }

echo ""

if [ "$HAS_GO" = false ]; then
  echo -e "  ${RED}✗${RESET} Go is required. Install it from https://go.dev/dl/ and re-run."
  exit 1
fi

if [ "$HAS_GCC" = false ]; then
  echo ""
  echo -e "  ${RED}✗${RESET} GCC is required for Go DuckDB (CGO). Please install it and re-run."
  exit 1
fi

# Create permanent directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR/bin"
mkdir -p "$DATA_DIR/frontend"

# Clone repo
TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo -e "  ${CYAN}◆${RESET} Cloning TRAKSHYA WAF..."
(
  git clone --depth=1 "https://github.com/${REPO}.git" "$TMP_DIR/repo" 2>&1 | tail -1
) && echo -e "  ${GREEN}✓${RESET} Repository cloned." || {
  echo -e "  ${RED}✗${RESET} Failed to clone repository."
  exit 1
}

cd "$TMP_DIR/repo"

# Copy frontend to permanent location
cp -r frontend/* "$DATA_DIR/frontend/" 2>/dev/null || true

# Build Rust proxy (optional, with timeout)
if [ "$HAS_CARGO" = true ] && [ -d "rust" ]; then
  echo ""
  echo -e "  ${CYAN}◆${RESET} [1/2] Building Rust proxy (this may take a few minutes)..."
  (
    cd rust
    if command -v timeout >/dev/null 2>&1; then
      timeout 600 cargo build --release 2>&1 | tail -5
    else
      cargo build --release &
      BUILD_PID=$!
      spinner "$BUILD_PID" "Building Rust proxy"
      wait "$BUILD_PID"
    fi
  ) && {
    echo -e "  ${GREEN}✓${RESET} Rust proxy built."
    cp "rust/target/release/trakshya-proxy" "$DATA_DIR/bin/"
  } || echo -e "  ${YELLOW}⚠${RESET} Rust proxy build skipped (non-critical)."
else
  echo -e "  ${YELLOW}⚠${RESET} [1/2] Cargo not found; skipping Rust proxy build (optional)."
fi

# Build Go API
echo ""
echo -e "  ${CYAN}◆${RESET} [2/2] Building Go management API..."
(
  cd go
  CGO_ENABLED=1 go build -o "$DATA_DIR/bin/trakshya-api" ./cmd/trakshya-api/
) && echo -e "  ${GREEN}✓${RESET} Go API built." || {
  echo -e "  ${RED}✗${RESET} Go build failed."
  exit 1
}

# Install launcher
echo ""
echo -e "  ${CYAN}◆${RESET} Installing launcher..."

cat >"$INSTALL_DIR/$BIN_NAME" <<LAUNCHER
#!/usr/bin/env bash
set -euo pipefail
DATA_DIR="$DATA_DIR"
DASHBOARD_PORT="\${TRAKSHYA_DASHBOARD_PORT:-${DASHBOARD_PORT}}"
PROXY_PORT="\${TRAKSHYA_PROXY_PORT:-${PROXY_PORT}}"
RUST_BIN="\$DATA_DIR/bin/trakshya-proxy"
API_BIN="\$DATA_DIR/bin/trakshya-api"

echo ""
echo -e "  \033[1;35mTRAKSHYA WAF\033[0m — Starting..."
echo ""

cleanup() {
  echo ""
  echo "  Shutting down..."
  [ -n "\${API_PID:-}" ] && kill "\$API_PID" 2>/dev/null || true
  [ -n "\${PROXY_PID:-}" ] && kill "\$PROXY_PID" 2>/dev/null || true
  echo "  Stopped."
}
trap cleanup EXIT

export TRAKSHYA_MGMT_PORT="\$DASHBOARD_PORT"
export TRAKSHYA_DUCKDB_PATH="\${TRAKSHYA_DUCKDB_PATH:-\$DATA_DIR/trakshya_events.duckdb}"
export TRAKSHYA_FRONTEND_DIR="\$DATA_DIR/frontend"

if [ ! -x "\$API_BIN" ]; then
  echo "  API binary missing: \$API_BIN (re-run the installer)"
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

# Add to PATH if not already there
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  SHELL_CONFIG="${HOME}/.bashrc"
  if [ -n "${ZSH_VERSION:-}" ]; then
    SHELL_CONFIG="${HOME}/.zshrc"
  fi
  echo "" >> "$SHELL_CONFIG"
  echo "# TRAKSHYA WAF" >> "$SHELL_CONFIG"
  echo "export PATH=\"\${PATH}:${INSTALL_DIR}\"" >> "$SHELL_CONFIG"
  echo -e "  ${CYAN}◇${RESET} Added ${INSTALL_DIR} to PATH in ${SHELL_CONFIG}"
fi

echo ""
echo -e "  ┌──────────────────────────────────────────────────┐"
echo -e "  │  ${BOLD}${PINK}TRAKSHYA WAF${RESET} — Installed                         │"
echo -e "  ├──────────────────────────────────────────────────┤"
echo -e "  │                                                  │"
echo -e "  │  ${GREEN}✓${RESET} Launcher: ${INSTALL_DIR}/${BIN_NAME}                  │"
echo -e "  │  ${GREEN}✓${RESET} API:      \$HOME/.local/share/trakshya/bin/  │"
if [ -x "$DATA_DIR/bin/trakshya-proxy" ]; then
  echo -e "  │  ${GREEN}✓${RESET} Proxy:    \$HOME/.local/share/trakshya/bin/  │"
fi
echo -e "  │                                                  │"
echo -e "  │  ${BOLD}Run:${RESET} ${CYAN}${BIN_NAME}${RESET}                                    │"
echo -e "  │  ${BOLD}Open:${RESET} ${CYAN}http://localhost:${DASHBOARD_PORT}${RESET}                         │"
echo -e "  │                                                  │"
echo -e "  └──────────────────────────────────────────────────┘"
echo ""

# Offer to start now
read -r -p "  Start TRAKSHYA WAF now? [Y/n] " yn
yn=${yn:-Y}
if [[ $yn =~ ^[Yy]$ ]]; then
  echo ""
  echo -e "  ${CYAN}▶${RESET} Launching..."
  "${INSTALL_DIR}/${BIN_NAME}"
fi
