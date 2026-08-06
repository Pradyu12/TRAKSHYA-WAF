#!/bin/bash
# TRAKSHYA-WAF — Cross-platform start script (macOS / Linux)
# Starts upstream server, Go API, Rust WAF proxy, and opens dashboard in browser.

set -e

UPSTREAM_PORT="${UPSTREAM_PORT:-3000}"
API_PORT="${API_PORT:-8000}"
PROXY_PORT="${PROXY_PORT:-8080}"
DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Check binaries exist ──────────────────────────────────────────
for bin in "$DIR/build/trakshya-api" "$DIR/build/trakshya-proxy"; do
  if [ ! -f "$bin" ]; then
    echo -e "${RED}Error: Binary not found: $bin${NC}"
    echo "Run 'make build' or build manually first."
    exit 1
  fi
done

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║         TRAKSHYA-WAF — Starting...       ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ── Kill old processes ──────────────────────────────────────────────
echo -e "${RED}[1/5]${NC} Cleaning up old processes..."
pkill -f "trakshya-api" 2>/dev/null || true
pkill -f "trakshya-proxy" 2>/dev/null || true
pkill -f "server.js" 2>/dev/null || true
sleep 1
echo -e "      Done.\n"

# ── Start upstream server ──────────────────────────────────────────
echo -e "${GREEN}[2/5]${NC} Starting upstream server on port ${UPSTREAM_PORT}..."
UPSTREAM_PORT=$UPSTREAM_PORT node "$DIR/server.js" > /tmp/trakshya-upstream.log 2>&1 &
UPSTREAM_PID=$!
sleep 2
if kill -0 $UPSTREAM_PID 2>/dev/null; then
    echo -e "      ${GREEN}OK${NC} (PID $UPSTREAM_PID)"
else
    echo -e "      ${RED}FAILED${NC} — check /tmp/trakshya-upstream.log"
fi
echo ""

# ── Start Go API ───────────────────────────────────────────────────
echo -e "${GREEN}[3/5]${NC} Starting Go API on port ${API_PORT}..."
TRAKSHYA_FRONTEND_DIR="$DIR/frontend" \
TRAKSHYA_DUCKDB_PATH="$DIR/trakshya_events.db" \
"$DIR/build/trakshya-api" > /tmp/trakshya-api.log 2>&1 &
API_PID=$!
sleep 3
if kill -0 $API_PID 2>/dev/null; then
    echo -e "      ${GREEN}OK${NC} (PID $API_PID)"
else
    echo -e "      ${RED}FAILED${NC} — check /tmp/trakshya-api.log"
fi
echo ""

# ── Start WAF Proxy ────────────────────────────────────────────────
echo -e "${GREEN}[4/5]${NC} Starting WAF Proxy on port ${PROXY_PORT}..."
TRAKSHYA_DUCKDB_PATH="$DIR/trakshya_events.duckdb" \
TRAKSHYA_MGMT_API_URL="http://127.0.0.1:${API_PORT}" \
TRAKSHYA_UPSTREAM_URL="http://127.0.0.1:${UPSTREAM_PORT}" \
"$DIR/build/trakshya-proxy" > /tmp/trakshya-proxy.log 2>&1 &
PROXY_PID=$!
sleep 3
if kill -0 $PROXY_PID 2>/dev/null; then
    echo -e "      ${GREEN}OK${NC} (PID $PROXY_PID)"
else
    echo -e "      ${RED}FAILED${NC} — check /tmp/trakshya-proxy.log"
fi
echo ""

# ── Open browser ───────────────────────────────────────────────────
echo -e "${GREEN}[5/5]${NC} Opening dashboard in browser..."
if command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:${API_PORT}" 2>/dev/null &
elif command -v open &>/dev/null; then
    open "http://localhost:${API_PORT}"
fi

# ── Summary ────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}  ═══════════════════════════════════════════${NC}"
echo -e "  Upstream Server : ${GREEN}http://localhost:${UPSTREAM_PORT}${NC}"
echo -e "  Go API          : ${GREEN}http://localhost:${API_PORT}${NC}"
echo -e "  WAF Proxy       : ${GREEN}http://localhost:${PROXY_PORT}${NC}"
echo -e "  Dashboard       : ${GREEN}http://localhost:${API_PORT}${NC} (open in browser)"
echo ""
echo -e "  Traffic flows: Client → WAF Proxy (${PROXY_PORT}) → Upstream (${UPSTREAM_PORT})"
echo -e "${CYAN}${BOLD}  ═══════════════════════════════════════════${NC}"
echo ""
echo -e "  Logs: /tmp/trakshya-{upstream,api,proxy}.log"
echo -e "  Press Ctrl+C to stop all services."
echo ""

# ── Wait for Ctrl+C ───────────────────────────────────────────────
cleanup() {
    echo -e "\n${RED}Stopping services...${NC}"
    kill $UPSTREAM_PID $API_PID $PROXY_PID 2>/dev/null || true
    pkill -f "trakshya-api" 2>/dev/null || true
    pkill -f "trakshya-proxy" 2>/dev/null || true
    pkill -f "server.js" 2>/dev/null || true
    echo -e "${GREEN}All services stopped.${NC}"
}
trap cleanup EXIT INT TERM

wait
