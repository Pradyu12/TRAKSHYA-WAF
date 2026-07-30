#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
CONFIG="${ROOT_DIR}/config/trakshya.yaml"

cleanup() {
  echo ""
  echo "Shutting down TRAKSHYA-WAF..."
  kill $PID_API $PID_PROXY 2>/dev/null || true
  wait 2>/dev/null || true
  echo "All components stopped."
}
trap cleanup SIGINT SIGTERM EXIT

echo "Starting TRAKSHYA-WAF..."
echo "======================="

# Start Go management API
export TRAKSHYA_MGMT_PORT=8000
export TRAKSHYA_DUCKDB_PATH="${TRAKSHYA_DUCKDB_PATH:-${ROOT_DIR}/trakshya_events.duckdb}"
export TRAKSHYA_FRONTEND_DIR="${ROOT_DIR}/frontend"
echo "  Starting Go management API on :8000..."
"${BUILD_DIR}/trakshya-api" &
PID_API=$!
sleep 1

# Start Rust proxy (if built)
if [ -x "${ROOT_DIR}/rust/target/release/trakshya-proxy" ]; then
  export TRAKSHYA_CONFIG="${CONFIG}"
  export TRAKSHYA_PROXY_PORT=8080
  export TRAKSHYA_UPSTREAM_URL=http://localhost:8000
  export TRAKSHYA_MGMT_API_URL=http://localhost:8000
  export RUST_LOG=info
  echo "  Starting Rust proxy on :8080..."
  "${ROOT_DIR}/rust/target/release/trakshya-proxy" &
  PID_PROXY=$!
else
  echo "  Skipping Rust proxy (binary not found - run 'scripts/build-all.sh' first)"
fi

echo "======================="
echo "TRAKSHYA-WAF is running:"
echo "  API:    http://localhost:8000"
[ -n "${PID_PROXY:-}" ] && echo "  Proxy:  http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop all components."

wait
