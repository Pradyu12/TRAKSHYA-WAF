#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
CONFIG="${ROOT_DIR}/config/kalki.yaml"

if [ ! -f "${BUILD_DIR}/kalki-proxy" ] || [ ! -f "${BUILD_DIR}/kalki-api" ] || [ ! -f "${BUILD_DIR}/kalki-systemd" ]; then
    echo "Build artifacts not found. Run 'scripts/build-all.sh' first."
    exit 1
fi

mkdir -p /var/lib/kalki 2>/dev/null || sudo mkdir -p /var/lib/kalki 2>/dev/null

cleanup() {
    echo ""
    echo "Shutting down KALKI-WAF..."
    kill $PID_API $PID_SYSTEMD $PID_PROXY 2>/dev/null || true
    wait 2>/dev/null || true
    echo "All components stopped."
}
trap cleanup SIGINT SIGTERM EXIT

echo "Starting KALKI-WAF..."
echo "======================="

# Start Go management API
export KALKI_MGMT_PORT=8000
export KALKI_DB_PATH=/var/lib/kalki/kalki.db
echo "  Starting Go management API on :8000..."
"${BUILD_DIR}/kalki-api" &
PID_API=$!
sleep 1

# Start C system monitor 
export KALKI_CONFIG="${CONFIG}"
echo "  Starting C system monitor on :9001..."
sudo "${BUILD_DIR}/kalki-systemd" &
PID_SYSTEMD=$!
sleep 1

# Start Rust proxy
export KALKI_CONFIG="${CONFIG}"
export KALKI_PROXY_PORT=8080
export KALKI_UPSTREAM_URL=http://localhost:3000
export KALKI_MGMT_API_URL=http://localhost:8000
export RUST_LOG=info
echo "  Starting Rust proxy on :8080..."
"${BUILD_DIR}/kalki-proxy" &
PID_PROXY=$!

echo "======================="
echo "KALKI-WAF is running:"
echo "  Proxy:  http://localhost:8080"
echo "  API:    http://localhost:8000"
echo "  System: http://localhost:9001"
echo ""
echo "Press Ctrl+C to stop all components."

wait
