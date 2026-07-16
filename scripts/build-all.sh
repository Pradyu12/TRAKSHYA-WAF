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
cargo build --release 2>&1 | tail -5
cp "${ROOT_DIR}/rust/target/release/trakshya-proxy" "${BUILD_DIR}/"
echo "Rust proxy built: ${BUILD_DIR}/trakshya-proxy"

# Build Go management API
echo ""
cd "${ROOT_DIR}/go"
go build -o "${BUILD_DIR}/trakshya-api" ./cmd/trakshya-api/ 2>&1
echo "Go API built: ${BUILD_DIR}/trakshya-api"

# Build C system monitor
echo ""
echo "--- Building C system monitor (trakshya-systemd) ---"
cd "${ROOT_DIR}/c"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3
make -j$(nproc) 2>&1 | tail -5
cp "${ROOT_DIR}/c/build/trakshya-systemd" "${BUILD_DIR}/"
echo "C system monitor built: ${BUILD_DIR}/trakshya-systemd"

echo ""
echo "=== All components built successfully ==="
echo "  Proxy:       ${BUILD_DIR}/trakshya-proxy"
echo "  API:         ${BUILD_DIR}/trakshya-api"
echo "  System Mon:  ${BUILD_DIR}/trakshya-systemd"
echo ""
echo "Run './scripts/run-all.sh' to start all components"
