#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build"
CONFIG="${REPO_ROOT}/config/trakshya.yaml"

export TRAKSHYA_CONFIG="${CONFIG}"
export TRAKSHYA_MGMT_API_URL="http://127.0.0.1:8000"
export TRAKSHYA_PROXY_PORT=8080
export TRAKSHYA_UPSTREAM_URL="http://127.0.0.1:3000"
export TRAKSHYA_API_PORT=8000
export RUST_LOG=info

if [ ! -f "${BUILD_DIR}/trakshya-proxy" ] || [ ! -f "${BUILD_DIR}/trakshya-api" ]; then
  echo "Missing build artifacts. Run scripts/build-all.sh first."
  exit 1
fi

trap 'kill $PID_API $PID_PROXY 2>/dev/null || true' SIGINT SIGTERM EXIT

echo "Starting TRAKSHYA WAF..."
"${BUILD_DIR}/trakshya-api" &
PID_API=$!
sleep 1

"${BUILD_DIR}/trakshya-proxy" &
PID_PROXY=$!
sleep 1

python3 "${REPO_ROOT}/scripts/smoke-test.py"

wait
