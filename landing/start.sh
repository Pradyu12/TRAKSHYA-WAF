#!/usr/bin/env bash
set -euo pipefail

# ── Colors ──────────────────────────────────────────────
G='\033[0;32m'    # green
DG='\033[2;32m'   # dim green
CY='\033[0;36m'   # cyan
R='\033[0;31m'    # red
B='\033[1m'       # bold
DIM='\033[2m'     # dim
RST='\033[0m'     # reset

# ── Helpers ─────────────────────────────────────────────
spinner() {
  local msg="$1" dur="${2:-2}" i=0 end
  local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  end=$((SECONDS + dur))
  while [ $SECONDS -lt $end ]; do
    printf "\r  ${CY}%s${RST} %s" "${chars:i++%10:1}" "$msg"
    sleep 0.1
  done
  printf "\r                              "
}

progress() {
  local label="$1" width=30 i=0 pct
  printf "\n"
  while [ $i -le $width ]; do
    pct=$(( i * 100 / width ))
    filled=$(printf '%*s' "$i" '' | tr ' ' '█')
    empty=$(printf '%*s' $((width - i)) '' | tr ' ' '░')
    printf "\r  ${G}%-20s${RST} [${G}%s${RST}%s] %3d%%" "$label" "$filled" "$empty" "$pct"
    sleep 0.03
    i=$((i + 1))
  done
  printf "\n"
}

type_line() {
  local line="$1" delay="${2:-0.02}" i
  printf "  ${DG}> ${RST}"
  for (( i=0; i<${#line}; i++ )); do
    printf "%s" "${line:$i:1}"
    sleep "$delay"
  done
  printf "\n"
}

box_line() {
  local content="$1" width=50
  local pad=$((width - 4 - ${#content}))
  printf "  ${CY}│${RST}  %s%*s${CY}│${RST}\n" "$content" "$pad" ""
}

# ── Banner ──────────────────────────────────────────────
clear
echo ""
echo -e "  ${G}     ████████╗██╗  ██╗██╗   ██╗██╗     ██╗  ██╗██╗   ██╗███████╗${RST}"
echo -e "  ${G}     ╚══██╔══╝██║  ██║██║   ██║██║     ██║  ██║██║   ██║██╔════╝${RST}"
echo -e "  ${G}        ██║   ███████║██║   ██║██║     ███████║██║   ██║███████╗${RST}"
echo -e "  ${G}        ██║   ██╔══██║██║   ██║██║     ██╔══██║██║   ██║╚════██║${RST}"
echo -e "  ${G}        ██║   ██║  ██║╚██████╔╝███████╗██║  ██║╚██████╔╝███████║${RST}"
echo -e "  ${G}        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝${RST}"
echo -e "  ${DIM}                    WAF v2.0 — Divine Eagle Guardian${RST}"
echo ""

# ── Boot sequence ───────────────────────────────────────
sleep 0.3
type_line "[INITIALIZING DEFENSE SYSTEMS...]" 0.015
sleep 0.2
type_line "[LOADING THREAT SIGNATURES...]" 0.015
sleep 0.2
type_line "[ESTABLISHING SECURE CHANNEL...]" 0.015
sleep 0.4

# ── Dependency checks ───────────────────────────────────
echo ""
echo -e "  ${B}${G}── DEPENDENCY CHECK ─────────────────────────────────────${RST}"

spinner "Checking Node.js..." 2

if ! command -v node &>/dev/null; then
  echo -e "  ${R}✗${RST} Node.js ${R}NOT FOUND${RST}"
  echo -e "    Install: curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -"
  echo -e "    Or visit: https://nodejs.org/"
  exit 1
fi

NODE_VER=$(node -v 2>/dev/null)
echo -e "  ${G}✓${RST} Node.js ${G}${NODE_VER}${RST}"

spinner "Checking curl..." 1

if ! command -v curl &>/dev/null; then
  echo -e "  ${R}✗${RST} curl ${R}NOT FOUND${RST}"
  exit 1
fi

echo -e "  ${G}✓${RST} curl ${G}$(curl --version 2>/dev/null | head -1 | awk '{print $2}')${RST}"
sleep 0.3

# ── Download phase ──────────────────────────────────────
echo ""
echo -e "  ${B}${G}── ACQUISITION ──────────────────────────────────────────${RST}"

if [ -f "server.js" ] && [ -d "frontend" ]; then
  REPO_DIR="$(pwd)"
  echo -e "  ${CY}●${RST} Local repo detected: ${CY}${REPO_DIR}${RST}"
else
  REPO_DIR="/tmp/trakshya-waf-$$"
  rm -rf "${REPO_DIR}"
  mkdir -p "${REPO_DIR}/frontend/static"

  BASE="https://raw.githubusercontent.com/Pradyu12/TRAKSHYA-WAF/main"

  echo -e "  ${CY}●${RST} Target: ${CY}${REPO_DIR}${RST}"
  echo ""

  progress "server.js" &
  curl -fsSL "${BASE}/server.js" -o "${REPO_DIR}/server.js" 2>/dev/null
  wait

  progress "dashboard.html" &
  curl -fsSL "${BASE}/frontend/dashboard.html" -o "${REPO_DIR}/frontend/dashboard.html" 2>/dev/null
  wait

  echo -e "  ${CY}●${RST} Fetching globe assets..."
  curl -fsSL "${BASE}/frontend/static/earth.glb" -o "${REPO_DIR}/frontend/static/earth.glb" 2>/dev/null &
  curl -fsSL "${BASE}/frontend/static/earth.jpg" -o "${REPO_DIR}/frontend/static/earth.jpg" 2>/dev/null &
  wait

  echo -e "  ${G}✓${RST} All files acquired"
fi

cd "${REPO_DIR}"

# ── Cleanup on exit ─────────────────────────────────────
cleanup() {
  echo ""
  echo -e "  ${DIM} shutting down defense systems...${RST}"
  if [[ "${REPO_DIR}" == /tmp/* ]] && [ -d "${REPO_DIR}" ]; then
    rm -rf "${REPO_DIR}"
  fi
}
trap cleanup EXIT

# ── Launch ──────────────────────────────────────────────
PORT="${TRAKSHYA_PORT:-8000}"
echo ""
echo -e "  ${B}${G}── SYSTEM READY ─────────────────────────────────────────${RST}"
echo ""
box_line ""
box_line "  Dashboard:    http://localhost:${PORT}"
box_line "  Proxy:        http://localhost:8080"
box_line "  SSE Stream:   http://localhost:${PORT}/api/stream"
box_line ""
echo -e "  ${CY}└────────────────────────────────────────────────────────┘${RST}"
echo ""
echo -e "  ${DIM}Press Ctrl+C to terminate.${RST}"
echo ""

exec node server.js
