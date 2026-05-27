#!/bin/bash
# Build KALKI Desktop standalone executable
# Usage: bash build-desktop.sh

set -e
cd "$(dirname "$0")"

echo "==> Installing build dependencies..."
pip3 install pyinstaller pillow requests sseclient-py --quiet

echo "==> Building KALKI-Desktop..."
pyinstaller --onefile --windowed \
  --name "KALKI-Desktop" \
  --add-data "$(pwd)/frontend/kalki_waf_logo.png:." \
  --icon "$(pwd)/frontend/kalki_waf_logo.png" \
  --hidden-import PIL \
  --hidden-import PIL._tkinter_finder \
  --distpath dist \
  --workpath /tmp/kalki_build \
  --specpath /tmp/kalki_build \
  --noconfirm \
  kalki-desktop.py

echo ""
echo "==> Done!"
ls -lh "dist/KALKI-Desktop"
echo ""
echo "Run: ./dist/KALKI-Desktop"
echo "Or install system-wide: sudo cp dist/KALKI-Desktop /usr/local/bin/kalki-desktop"
