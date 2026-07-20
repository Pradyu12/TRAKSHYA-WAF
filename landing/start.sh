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

spinner "Checking Docker..." 2

if ! command -v docker &>/dev/null; then
  echo -e "  ${R}✗${RST} Docker ${R}NOT FOUND${RST}"
  echo -e "    Install: https://docs.docker.com/get-docker/"
  exit 1
fi

DOCKER_VER=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')
echo -e "  ${G}✓${RST} Docker ${G}${DOCKER_VER}${RST}"

spinner "Checking Docker Compose..." 2

if ! docker compose version &>/dev/null 2>&1; then
  echo -e "  ${R}✗${RST} Docker Compose ${R}NOT FOUND${RST}"
  echo -e "    Install: https://docs.docker.com/compose/install/"
  exit 1
fi

COMPOSE_VER=$(docker compose version 2>/dev/null | awk '{print $4}')
echo -e "  ${G}✓${RST} Docker Compose ${G}${COMPOSE_VER}${RST}"

# ── Clone phase ─────────────────────────────────────────
echo ""
echo -e "  ${B}${G}── ACQUISITION ──────────────────────────────────────────${RST}"

if [ -f "docker-compose.stack.yml" ] && [ -d "frontend" ]; then
  REPO_DIR="$(pwd)"
  echo -e "  ${CY}●${RST} Local repo detected: ${CY}${REPO_DIR}${RST}"
else
  REPO_DIR="/tmp/trakshya-waf-$$"
  rm -rf "${REPO_DIR}"
  mkdir -p "${REPO_DIR}"

  echo -e "  ${CY}●${RST} Cloning TRAKSHYA-WAF..."
  spinner "Cloning repository..." 3
  git clone --depth 1 https://github.com/Pradyu12/TRAKSHYA-WAF.git "${REPO_DIR}" 2>/dev/null
  echo -e "  ${G}✓${RST} Repository cloned"
fi

cd "${REPO_DIR}"

# ── Cleanup on exit ─────────────────────────────────────
cleanup() {
  echo ""
  echo -e "  ${DIM}shutting down defense systems...${RST}"
  docker compose -f docker-compose.stack.yml down 2>/dev/null || true
  if [[ "${REPO_DIR}" == /tmp/* ]] && [ -d "${REPO_DIR}" ]; then
    rm -rf "${REPO_DIR}"
  fi
}
trap cleanup EXIT INT TERM

# ── Build & Launch ──────────────────────────────────────
echo ""
echo -e "  ${B}${G}── BUILDING CONTAINERS ──────────────────────────────────${RST}"

progress "Building images" &
docker compose -f docker-compose.stack.yml up --build -d 2>&1 | tail -1 &
wait

echo -e "  ${G}✓${RST} Containers built and started"

# ── Wait for health ─────────────────────────────────────
echo ""
echo -e "  ${B}${G}── HEALTH CHECK ────────────────────────────────────────${RST}"

MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    echo -e "  ${G}✓${RST} API is healthy"
    break
  fi
  spinner "Waiting for API..." 2
  WAITED=$((WAITED + 2))
done

if [ $WAITED -ge $MAX_WAIT ]; then
  echo -e "  ${R}✗${RST} API failed to start within ${MAX_WAIT}s"
  echo -e "  ${DIM}Check logs: docker compose -f docker-compose.stack.yml logs${RST}"
  exit 1
fi

# ── System Ready ────────────────────────────────────────
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

# ── Follow logs ─────────────────────────────────────────
docker compose -f docker-compose.stack.yml logs -f --tail=50
