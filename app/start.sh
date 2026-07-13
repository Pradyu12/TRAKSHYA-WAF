#!/bin/bash
# Trakshya WAF — Desktop Launcher
# Starts all backends then launches the Electron app

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Trakshya WAF Launcher ==="

# Set frontend directory for Go API
export KALKI_FRONTEND_DIR="$SCRIPT_DIR/renderer"

# Start backends
for bin in kalki-api kalki-proxy kalki-systemd; do
  if [ -f "bin/$bin" ]; then
    echo "Starting $bin..."
    if [ "$bin" = "kalki-systemd" ]; then
      bin/$bin &
    else
      bin/$bin --config "$SCRIPT_DIR/../config/kalki.yaml" &
    fi
    sleep 1
  else
    echo "Warning: bin/$bin not found"
  fi
done

# Wait for API to be ready
echo "Waiting for backends..."
for i in $(seq 1 30); do
  if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "API ready"
    break
  fi
  sleep 1
done

# Launch Electron
if command -v npx &> /dev/null; then
  npx electron .
elif command -v electron &> /dev/null; then
  electron .
else
  echo "Electron not found. Opening dashboard in browser..."
  xdg-open http://localhost:8000
fi
