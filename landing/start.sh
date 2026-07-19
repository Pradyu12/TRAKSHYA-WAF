#!/usr/bin/env bash
set -euo pipefail

PINK='\033[0;35m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "\n  ${BOLD}${PINK}TRAKSHYA WAF${RESET} — Starting...\n"

# Check Node.js
if ! command -v node &>/dev/null; then
  echo -e "  ${RED}x${RESET} Node.js is required. Install it:"
  echo -e "    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -"
  echo -e "    sudo apt-get install -y nodejs"
  echo -e "  Or visit: https://nodejs.org/"
  exit 1
fi

NODE_VER=$(node -v 2>/dev/null)
echo -e "  ${GREEN}v${RESET} Node.js ${NODE_VER}"

# Check curl
if ! command -v curl &>/dev/null; then
  echo -e "  ${RED}x${RESET} curl is required."
  exit 1
fi

# Check if we're already in the repo
if [ -f "server.js" ] && [ -d "frontend" ]; then
  REPO_DIR="$(pwd)"
  echo -e "  ${CYAN}*${RESET} Using local repo: ${REPO_DIR}"
else
  REPO_DIR="/tmp/trakshya-waf-$$"
  echo -e "  ${CYAN}*${RESET} Downloading TRAKSHYA WAF to ${REPO_DIR}..."
  rm -rf "${REPO_DIR}"
  mkdir -p "${REPO_DIR}/frontend/static"

  BASE="https://raw.githubusercontent.com/Pradyu12/TRAKSHYA-WAF/main"

  echo -e "  ${CYAN}*${RESET} Downloading server.js..."
  curl -fsSL "${BASE}/server.js" -o "${REPO_DIR}/server.js"

  echo -e "  ${CYAN}*${RESET} Downloading dashboard..."
  curl -fsSL "${BASE}/frontend/dashboard.html" -o "${REPO_DIR}/frontend/dashboard.html"

  echo -e "  ${CYAN}*${RESET} Downloading globe assets..."
  curl -fsSL "${BASE}/frontend/static/earth.glb" -o "${REPO_DIR}/frontend/static/earth.glb" 2>/dev/null || true
  curl -fsSL "${BASE}/frontend/static/earth.jpg" -o "${REPO_DIR}/frontend/static/earth.jpg" 2>/dev/null || true
fi

cd "${REPO_DIR}"

# Cleanup on exit (only remove if we downloaded to a temp dir)
cleanup() {
  echo -e "\n  ${PINK}TRAKSHYA WAF${RESET} stopped."
  if [[ "${REPO_DIR}" == /tmp/* ]] && [ -d "${REPO_DIR}" ]; then
    rm -rf "${REPO_DIR}"
  fi
}
trap cleanup EXIT

# Start server
PORT="${TRAKSHYA_PORT:-8000}"
echo -e "  ${GREEN}v${RESET} Dashboard:  http://localhost:${PORT}"
echo -e "  ${GREEN}v${RESET} Proxy:      http://localhost:8080"
echo -e "  ${GREEN}v${RESET} SSE Stream:  http://localhost:${PORT}/api/stream"
echo -e "\n  Press Ctrl+C to stop.\n"

exec node server.js
