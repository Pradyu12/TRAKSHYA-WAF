#!/usr/bin/env bash
set -euo pipefail

REPO="Pradyu12/TRAKSHYA-WAF"
BIN_NAME="trakshya-waf"
INSTALL_DIR="${HOME}/.local/bin"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
RST='\033[0m'

echo ""
echo -e "  ${BOLD}${CYAN}TRAKSHYA WAF v2.1${RST} — Installing via Docker"
echo ""

# Check dependencies
if ! command -v docker &>/dev/null; then
  echo -e "  ${RED}\u2716${RST} Docker is required."
  echo -e "    Install: https://docs.docker.com/get-docker/"
  exit 1
fi

if ! docker compose version &>/dev/null 2>&1; then
  echo -e "  ${RED}\u2716${RST} Docker Compose is required."
  echo -e "    Install: https://docs.docker.com/compose/install/"
  exit 1
fi

# Clone or detect repo
if [ -f "docker-compose.yml" ] && [ -d "go" ] && [ -d "frontend" ]; then
  REPO_DIR="$(pwd)"
  echo -e "  ${CYAN}\u25cf${RST} Local repo detected: ${REPO_DIR}"
else
  REPO_DIR="/tmp/trakshya-waf-$$"
  echo -e "  ${CYAN}\u25cf${RST} Cloning TRAKSHYA-WAF..."
  git clone --depth 1 "https://github.com/${REPO}.git" "${REPO_DIR}" 2>/dev/null
  echo -e "  ${GREEN}\u2714${RST} Repository cloned"
fi

cd "${REPO_DIR}"

# Build and start services
echo ""
echo -e "  ${CYAN}\u25cf${RST} Building and starting services..."
docker compose up --build -d 2>&1 | tail -1 || {
  echo -e "  ${RED}\u2716${RST} Docker build failed."
  echo -e "    Check: docker compose logs"
  exit 1
}

# Wait for API health
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
  if curl -sf http://localhost:8000/ready >/dev/null 2>&1; then
    echo -e "  ${GREEN}\u2714${RST} API is healthy (DuckDB ready)"
    break
  fi
  sleep 2
  WAITED=$((WAITED + 2))
done

if [ $WAITED -ge $MAX_WAIT ]; then
  echo -e "  ${RED}\u2716${RST} API failed to start within ${MAX_WAIT}s"
  echo -e "    Check: docker compose logs trakshya-api"
  exit 1
fi

# Install launcher
mkdir -p "${INSTALL_DIR}"
LAUNCHER="${INSTALL_DIR}/${BIN_NAME}"
cat >"${LAUNCHER}" <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
REPO_DIR="'"${REPO_DIR}"'"
echo "Starting TRAKSHYA WAF..."
cd "$REPO_DIR"
docker compose up -d
echo "Dashboard: http://localhost:8000"
echo "Press Ctrl+C to stop logs."
docker compose logs -f --tail=30
LAUNCHER
chmod +x "${LAUNCHER}"

echo ""
echo -e "  ${GREEN}\u2714${RST} Installed successfully!"
echo ""
echo -e "  Dashboard: ${CYAN}http://localhost:8000${RST}"
echo -e "  Proxy:     ${CYAN}http://localhost:8080${RST}"
echo ""
echo -e "  ${DIM}Run '${BIN_NAME}' to restart later.${RST}"
echo ""

# Open browser
if command -v xdg-open &>/dev/null; then
  xdg-open "http://localhost:8000" 2>/dev/null || true
elif command -v open &>/dev/null; then
  open "http://localhost:8000" 2>/dev/null || true
fi
