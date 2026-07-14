#!/usr/bin/env node
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const BIN_NAME = 'trakshya-waf';
const INSTALL_DIR = path.join(os.homedir(), '.local', 'bin');
const APPIMAGE_PATH = path.join(INSTALL_DIR, `${BIN_NAME}.AppImage`);
const SYMLINK_PATH = path.join(INSTALL_DIR, BIN_NAME);

function findBinary() {
  // Check symlink target
  if (fs.existsSync(SYMLINK_PATH)) {
    try {
      const target = fs.readlinkSync(SYMLINK_PATH);
      if (fs.existsSync(target)) return target;
    } catch (e) {}
  }
  // Check direct path
  if (fs.existsSync(APPIMAGE_PATH)) return APPIMAGE_PATH;
  // Check PATH
  try {
    const which = execSync(`which ${BIN_NAME} 2>/dev/null`).toString().trim();
    if (which) return which;
  } catch (e) {}
  return null;
}

const bin = findBinary();
if (!bin) {
  console.error(`
  \u001b[1m\u001b[35mTRAKSHYA WAF\u001b[0m

  \u001b[31m\u2716\u001b[0m Trakshya WAF is not installed.

  Install it:
    \u001b[36m$\u001b[0m \u001b[1mnpm install -g trakshya-waf\u001b[0m  (requires internet)

  Or download manually:
    \u001b[36m$\u001b[0m \u001b[1mcurl -fsSL https://trakshya.waf/install.sh | bash\u001b[0m

  Or get the AppImage from:
    https://github.com/Pradyu12/KALKI-WAF/releases
`);
  process.exit(1);
}

console.log(`
  \u001b[1m\u001b[35mTRAKSHYA WAF\u001b[0m
  \u001b[2mDivine Eagle Guardian for Your Web Applications\u001b[0m

  \u001b[36m\u25b6\u001b[0m Launching desktop dashboard...
  \u001b[2m  (Close this terminal to shut down all services)\u001b[0m
`);

try {
  execSync(`"${bin}"`, { stdio: 'inherit', cwd: os.homedir() });
} catch (e) {
  // AppImage closed
  process.exit(0);
}
