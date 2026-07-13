#!/bin/bash
set -euo pipefail

echo "=== Building KALKI-WAF ==="

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
mkdir -p "${BUILD_DIR}"

# Build Rust proxy
echo ""
echo "--- Building Rust proxy (kalki-proxy) ---"
cd "${ROOT_DIR}/rust"
cargo build --release 2>&1 | tail -5
cp "${ROOT_DIR}/rust/target/release/kalki-proxy" "${BUILD_DIR}/"
echo "Rust proxy built: ${BUILD_DIR}/kalki-proxy"

# Build Go management API
echo ""
echo "--- Building Go management API (kalki-api) ---"
cd "${ROOT_DIR}/go"
go mod tidy 2>/dev/null || true
go build -o "${BUILD_DIR}/kalki-api" ./cmd/kalki-api/ 2>&1
echo "Go API built: ${BUILD_DIR}/kalki-api"

# Build C system monitor
echo ""
echo "--- Building C system monitor (kalki-systemd) ---"
cd "${ROOT_DIR}/c"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3
make -j$(nproc) 2>&1 | tail -5
cp "${ROOT_DIR}/c/build/kalki-systemd" "${BUILD_DIR}/"
echo "C system monitor built: ${BUILD_DIR}/kalki-systemd"

echo ""
echo "=== All components built successfully ==="
echo "  Proxy:       ${BUILD_DIR}/kalki-proxy"
echo "  API:         ${BUILD_DIR}/kalki-api"
echo "  System Mon:  ${BUILD_DIR}/kalki-systemd"
echo ""
echo "Run './scripts/run-all.sh' to start all components"
