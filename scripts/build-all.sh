#!/bin/bash
set -euo pipefail

echo "=== Building TRAKSHYA-WAF ==="

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
mkdir -p "${BUILD_DIR}"

# Build Rust proxy
echo ""
echo "--- Building Rust proxy (trakshya-proxy) ---"
cd "${ROOT_DIR}/rust"
if command -v timeout >/dev/null 2>&1; then
  timeout 600 cargo build --release 2>&1 | tail -5
else
  cargo build --release 2>&1 | tail -5
fi
cp -f "${ROOT_DIR}/rust/target/release/trakshya-proxy" "${BUILD_DIR}/" 2>/dev/null || true
echo "Rust proxy built: ${BUILD_DIR}/trakshya-proxy"

# Build Go management API
echo ""
cd "${ROOT_DIR}/go"
CGO_ENABLED=1 go build -o "${BUILD_DIR}/trakshya-api" ./cmd/trakshya-api/ 2>&1
echo "Go API built: ${BUILD_DIR}/trakshya-api"

# Build C system monitor (optional, requires cmake)
echo ""
echo "--- Building C system monitor (trakshya-systemd) ---"
if command -v cmake >/dev/null 2>&1; then
  cd "${ROOT_DIR}/c"
  mkdir -p build && cd build
  cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3
  make -j$(nproc) 2>&1 | tail -5
  cp -f "${ROOT_DIR}/c/build/trakshya-systemd" "${BUILD_DIR}/" 2>/dev/null || true
  echo "C system monitor built: ${BUILD_DIR}/trakshya-systemd"
else
  echo "  cmake not found; skipping C system monitor (optional component)."
fi

echo ""
echo "=== All components built successfully ==="
echo "  Proxy:       ${BUILD_DIR}/trakshya-proxy"
echo "  API:         ${BUILD_DIR}/trakshya-api"
echo ""
echo "Run 'trakshya-waf' or './scripts/run-all.sh' to start all components"
