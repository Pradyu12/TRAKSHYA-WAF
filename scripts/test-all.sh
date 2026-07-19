#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

if [ ! -f "${BUILD_DIR}/trakshya-proxy" ] || [ ! -f "${BUILD_DIR}/trakshya-api" ] || [ ! -f "${BUILD_DIR}/trakshya-systemd" ]; then
    echo "Build artifacts not found. Run 'scripts/build-all.sh' first."
    exit 1
fi

mkdir -p /var/lib/trakshya 2>/dev/null || true

export TRAKSHYA_CONFIG="${ROOT_DIR}/config/trakshya.yaml"
export TRAKSHYA_DATABASE_URL="postgres://trakshya:***@localhost:5432/trakshya?sslmode=disable"
export TRAKSHYA_MGMT_PORT=8000
export TRAKSHYA_API_PORT=8000
export TRAKSHYA_PROXY_PORT=8080
export TRAKSHYA_UPSTREAM_URL="http://localhost:3000"
export TRAKSHYA_MGMT_API_URL="http://localhost:8000"
export TRAKSHYA_FRONTEND_DIR="${ROOT_DIR}/frontend"
export RUST_LOG=info

echo "Starting TRAKSHYA-WAF services for tests..."
"${BUILD_DIR}/trakshya-api" > /tmp/trakshya-api.log 2>&1 &
PID_API=$!
"${BUILD_DIR}/trakshya-proxy" > /tmp/trakshya-proxy.log 2>&1 &
PID_PROXY=$!

cleanup() {
    echo ""
    echo "Shutting down services..."
    kill $PID_API $PID_PROXY 2>/dev/null || true
    wait 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT

sleep 2

echo "Running smoke tests..."
python3 "${ROOT_DIR}/scripts/smoke-test.py"

echo "Running regression tests..."
python3 "${ROOT_DIR}/scripts/regression.py"

echo "All tests completed."
