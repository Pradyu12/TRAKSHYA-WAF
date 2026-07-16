#!/usr/bin/env bash
set -euo pipefail

REPO="Pradyu12/TRAKSHYA-WAF"
BIN_NAME="trakshya-waf"
INSTALL_DIR="${HOME}/.local/bin"
APPIMAGE_PATH="${INSTALL_DIR}/${BIN_NAME}.AppImage"
SYMLINK_PATH="${INSTALL_DIR}/${BIN_NAME}"

# Colors
PINK='\033[0;35m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "\n  ${BOLD}${PINK}TRAKSHYA WAF${RESET} — Installing...\n"

# Check dependencies
if ! command -v curl &>/dev/null; then
  echo -e "  ${RED}\u2716${RESET} curl is required. Install it: sudo apt install curl"
  exit 1
fi

# Ensure install dir
mkdir -p "${INSTALL_DIR}"

# Get latest release info
echo -e "  ${CYAN}\u25cf${RESET} Fetching latest release..."
LATEST_JSON=$(curl -sfL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)

if [ -z "$LATEST_JSON" ]; then
  echo -e "  ${RED}\u2716${RESET} Failed to fetch release info. Check your internet connection."
  exit 1
fi

# Extract download URL for AppImage
DOWNLOAD_URL=$(echo "$LATEST_JSON" | grep -o '"browser_download_url": *"[^"]*\.AppImage"' | cut -d'"' -f4)

if [ -z "$DOWNLOAD_URL" ]; then
  echo -e "  ${RED}\u2716${RESET} No AppImage found in latest release."
  echo -e "  Download manually: https://github.com/${REPO}/releases"
  exit 1
fi

# Download
echo -e "  ${CYAN}\u25cf${RESET} Downloading Trakshya WAF..."
echo -e "  ${CYAN}\u25cf${RESET} URL: ${DOWNLOAD_URL}"

curl -#fL "${DOWNLOAD_URL}" -o "${APPIMAGE_PATH}"

if [ $? -ne 0 ] || [ ! -f "${APPIMAGE_PATH}" ]; then
  echo -e "  ${RED}\u2716${RESET} Download failed."
  exit 1
fi

chmod +x "${APPIMAGE_PATH}"

# Create symlink
if [ -L "${SYMLINK_PATH}" ] || [ -f "${SYMLINK_PATH}" ]; then
  rm -f "${SYMLINK_PATH}"
fi
ln -sf "${APPIMAGE_PATH}" "${SYMLINK_PATH}"

# Ensure INSTALL_DIR is in PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  SHELL_CONFIG="${HOME}/.bashrc"
  if [ -f "${HOME}/.zshrc" ]; then
    SHELL_CONFIG="${HOME}/.zshrc"
  fi
  echo "export PATH=\"\${PATH}:${INSTALL_DIR}\"" >> "${SHELL_CONFIG}"
  echo -e "  ${CYAN}\u25cf${RESET} Added ${INSTALL_DIR} to PATH in ${SHELL_CONFIG}"
fi

echo -e "\n  ${GREEN}\u2714${RESET} Installed successfully!\n"
echo -e "  Binary:  ${APPIMAGE_PATH}"
echo -e "  Symlink: ${SYMLINK_PATH}"
echo -e "\n  Run ${BOLD}${BIN_NAME}${RESET} to start the dashboard.\n"
echo -e "  Or reopen your terminal and just type: ${BOLD}${BIN_NAME}${RESET}\n"

# Offer to start now
read -r -p "  Start Trakshya WAF now? [Y/n] " yn
yn=${yn:-Y}
if [[ "$yn" =~ ^[Yy]$ ]]; then
  echo -e "\n  ${CYAN}\u25b6${RESET} Launching..."
  "${APPIMAGE_PATH}"
fi
