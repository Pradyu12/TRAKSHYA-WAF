const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { createGunzip } = require('zlib');

const REPO = 'Pradyu12/KALKI-WAF';
const BIN_NAME = 'trakshya-waf';
const INSTALL_DIR = path.join(os.homedir(), '.local', 'bin');
const APPIMAGE_PATH = path.join(INSTALL_DIR, `${BIN_NAME}.AppImage`);
const SYMLINK_PATH = path.join(INSTALL_DIR, BIN_NAME);

console.log(`\n  \u001b[1m\u001b[35mTRAKSHYA WAF\u001b[0m — Installing...\n`);

function getLatestRelease() {
  return new Promise((resolve, reject) => {
    https.get(`https://api.github.com/repos/${REPO}/releases/latest`, {
      headers: { 'User-Agent': 'trakshya-waf-installer' }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const release = JSON.parse(data);
          const asset = release.assets.find(a => a.name.endsWith('.AppImage'));
          if (asset) resolve(asset.browser_download_url);
          else reject(new Error('No AppImage found in latest release'));
        } catch (e) {
          reject(new Error('Failed to parse release data'));
        }
      });
    }).on('error', reject);
  });
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, {
      headers: { 'User-Agent': 'trakshya-waf-installer' }
    }, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`Download failed: HTTP ${res.statusCode}`));
        return;
      }
      const total = parseInt(res.headers['content-length'] || '0');
      let downloaded = 0;
      res.on('data', chunk => {
        downloaded += chunk.length;
        const pct = total ? Math.round(downloaded / total * 100) : 0;
        process.stdout.write(`\r  \u001b[36m\u25cf\u001b[0m Downloading... ${pct}%`);
      });
      res.pipe(file);
      file.on('finish', () => {
        file.close();
        process.stdout.write('\n');
        resolve();
      });
    }).on('error', (err) => {
      fs.unlinkSync(dest);
      reject(err);
    });
  });
}

async function install() {
  try {
    // Ensure install directory
    if (!fs.existsSync(INSTALL_DIR)) {
      fs.mkdirSync(INSTALL_DIR, { recursive: true });
    }

    console.log(`  \u001b[36m\u25cf\u001b[0m Fetching latest release...`);
    const url = await getLatestRelease();
    console.log(`  \u001b[36m\u25cf\u001b[0m Downloading Trakshya WAF...`);

    await downloadFile(url, APPIMAGE_PATH);
    fs.chmodSync(APPIMAGE_PATH, 0o755);

    // Create symlink
    if (fs.existsSync(SYMLINK_PATH)) {
      fs.unlinkSync(SYMLINK_PATH);
    }
    fs.symlinkSync(APPIMAGE_PATH, SYMLINK_PATH);

    console.log(`\n  \u001b[32m\u2714\u001b[0m Installed successfully!\n`);
    console.log(`  Binary:  ${APPIMAGE_PATH}`);
    console.log(`  Symlink: ${SYMLINK_PATH}`);
    console.log(`\n  Run \u001b[1m${BIN_NAME}\u001b[0m or \u001b[1mnpx ${BIN_NAME}\u001b[0m to start.\n`);

  } catch (err) {
    console.error(`\n  \u001b[31m\u2716\u001b[0m Installation failed: ${err.message}\n`);
    console.log(`  Download manually: https://github.com/${REPO}/releases\n`);
    process.exit(1);
  }
}

install();
