#!/bin/bash
# Trakshya WAF — XDG autostart setup
# Run: bash scripts/autostart.sh

AUTOSTART_DIR="$HOME/.config/autostart"
DESKTOP_FILE="$AUTOSTART_DIR/trakshya-waf.desktop"

if [ ! -d "$AUTOSTART_DIR" ]; then
  mkdir -p "$AUTOSTART_DIR"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXEC_PATH="$SCRIPT_DIR/start.sh"

if [ ! -f "$EXEC_PATH" ]; then
  echo "Warning: start.sh not found at $EXEC_PATH"
  echo "Creating desktop file anyway with placeholder path."
fi

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Type=Application
Name=Trakshya WAF
Exec=$EXEC_PATH
Icon=$SCRIPT_DIR/assets/icon.png
Terminal=false
Categories=Security;Utility;
X-GNOME-Autostart-enabled=true
Comment=Trakshya WAF Security Dashboard
EOF

chmod 644 "$DESKTOP_FILE"
echo "Autostart file created: $DESKTOP_FILE"
