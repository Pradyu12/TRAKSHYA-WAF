const { app, BrowserWindow, Tray, Menu, Notification, ipcMain, nativeImage } = require('electron');
const { execFile, spawn } = require('child_process');
const path = require('path');
const http = require('http');
const fs = require('fs');

const BACKENDS = {
  api: { bin: 'trakshya-api', port: 8000, args: ['--config', '../config/trakshya.yaml'] },
  proxy: { bin: 'trakshya-proxy', port: 8080, args: ['--config', '../config/trakshya.yaml'] },
  cmon: { bin: 'trakshya-systemd', port: 9001, args: [] },
};

let mainWindow = null;
let tray = null;
let backendProcesses = {};
let backendRetries = { api: 0, proxy: 0, cmon: 0 };
const MAX_RETRIES = 3;
const RETRY_DELAY = 3000;
let unackCount = 0;

function getBinPath(name) {
  const ext = process.platform === 'win32' ? '.exe' : '';
  return path.join(__dirname, 'bin', name + ext);
}

function startBackend(name) {
  const backend = BACKENDS[name];
  const binPath = getBinPath(backend.bin);
  if (!fs.existsSync(binPath)) {
    console.warn(`Binary not found: ${binPath}`);
    return;
  }
  console.log(`Starting ${name} (${binPath})...`);
  const proc = execFile(binPath, backend.args, {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, TRAKSHYA_FRONTEND_DIR: path.join(__dirname, 'renderer') },
  }, (err, stdout, stderr) => {
    if (err && backendRetries[name] < MAX_RETRIES) {
      console.error(`${name} exited (${err.code}), restarting...`);
      backendRetries[name]++;
      setTimeout(() => startBackend(name), RETRY_DELAY);
    }
  });
  proc.stdout.on('data', d => process.stdout.write(`[${name}] ${d}`));
  proc.stderr.on('data', d => process.stderr.write(`[${name}] ${d}`));
  backendProcesses[name] = proc;
}

function stopAll() {
  Object.entries(backendProcesses).forEach(([name, proc]) => {
    if (proc && !proc.killed) {
      console.log(`Stopping ${name}...`);
      proc.kill('SIGTERM');
      setTimeout(() => { if (!proc.killed) proc.kill('SIGKILL'); }, 5000);
    }
  });
}

function waitForBackend(port, timeout = 15000) {
  return new Promise((resolve) => {
    const start = Date.now();
    function check() {
      const req = http.get(`http://localhost:${port}/health`, (res) => resolve(true));
      req.on('error', () => {
        if (Date.now() - start > timeout) resolve(false);
        else setTimeout(check, 500);
      });
      req.end();
    }
    check();
  });
}

function createTitleBar() {
  const titleBarPath = path.join(__dirname, 'renderer', 'titlebar.html');
  if (fs.existsSync(titleBarPath)) {
    return fs.readFileSync(titleBarPath, 'utf-8');
  }
  return '';
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    frame: false,
    transparent: false,
    backgroundColor: '#050010',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  const dashboardPath = path.join(__dirname, 'renderer', 'dashboard.html');
  if (fs.existsSync(dashboardPath)) {
    mainWindow.loadFile(dashboardPath);
  } else {
    mainWindow.loadURL('http://localhost:8000');
  }

  mainWindow.on('close', (e) => {
    if (tray) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => { mainWindow = null; });
}

function createTray() {
  const iconPath = path.join(__dirname, 'assets', 'tray-icon.png');
  let icon;
  if (fs.existsSync(iconPath)) {
    icon = nativeImage.createFromPath(iconPath);
  } else {
    icon = nativeImage.createEmpty();
  }
  tray = new Tray(icon);
  tray.setToolTip('Trakshya WAF');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Show Window', click: () => mainWindow && mainWindow.show() },
    { label: 'Status: Running', enabled: false },
    { type: 'separator' },
    { label: 'Quit', click: () => { tray = null; app.quit(); } },
  ]));
  tray.on('double-click', () => mainWindow && mainWindow.show());
}

function sendDesktopNotification(title, body) {
  if (Notification.isSupported()) {
    const notif = new Notification({ title, body, icon: path.join(__dirname, 'assets', 'icon.png') });
    notif.show();
  }
}

// IPC Handlers
ipcMain.handle('get-backend-status', () => ({
  api: backendProcesses.api && !backendProcesses.api.killed,
  proxy: backendProcesses.proxy && !backendProcesses.proxy.killed,
  cmon: backendProcesses.cmon && !backendProcesses.cmon.killed,
}));

ipcMain.handle('restart-backend', (_, name) => {
  if (backendProcesses[name] && !backendProcesses[name].killed) {
    backendProcesses[name].kill('SIGTERM');
  }
  backendRetries[name] = 0;
  startBackend(name);
  return true;
});

ipcMain.handle('get-auto-launch', () => {
  const desktopPath = path.join(os.homedir(), '.config', 'autostart', 'trakshya-waf.desktop');
  return fs.existsSync(desktopPath);
});

ipcMain.handle('set-auto-launch', (_, enabled) => {
  const autostartDir = path.join(os.homedir(), '.config', 'autostart');
  const desktopPath = path.join(autostartDir, 'trakshya-waf.desktop');
  if (enabled) {
    const execPath = process.env.APPIMAGE || process.execPath;
    const content = `[Desktop Entry]
Type=Application
Name=Trakshya WAF
Exec=${execPath} --hidden
Icon=trakshya-waf
Terminal=false
X-GNOME-Autostart-enabled=true
`;
    if (!fs.existsSync(autostartDir)) fs.mkdirSync(autostartDir, { recursive: true });
    fs.writeFileSync(desktopPath, content);
  } else {
    if (fs.existsSync(desktopPath)) fs.unlinkSync(desktopPath);
  }
  return true;
});

ipcMain.handle('get-version', () => app.getVersion());

ipcMain.on('quit', () => { tray = null; app.quit(); });
ipcMain.on('minimize-to-tray', () => mainWindow && mainWindow.hide());

// SSE monitoring for desktop notifications
function monitorSSE() {
  const req = http.get('http://localhost:8000/api/stream', (res) => {
    res.on('data', (chunk) => {
      try {
        const data = chunk.toString();
        if (data.startsWith('data: ')) {
          const parsed = JSON.parse(data.slice(6));
          if (parsed.alert && (parsed.alert.severity === 'critical' || parsed.alert.severity === 'high')) {
            unackCount++;
            sendDesktopNotification(
              `Trakshya: ${parsed.alert.severity.toUpperCase()} Alert`,
              `${parsed.alert.description || 'Security alert detected'}`
            );
            if (mainWindow) {
              mainWindow.webContents.send('notification', parsed.alert);
            }
            if (tray) {
              tray.setToolTip(`Trakshya WAF — ${unackCount} unacknowledged`);
            }
          }
        }
      } catch (e) {}
    });
    res.on('end', () => setTimeout(monitorSSE, 5000));
  });
  req.on('error', () => setTimeout(monitorSSE, 5000));
  req.end();
}

app.whenReady().then(async () => {
  console.log('Trakshya WAF v' + app.getVersion());

  Object.keys(BACKENDS).forEach(name => startBackend(name));

  console.log('Waiting for backends...');
  const apiReady = await waitForBackend(8000);
  if (!apiReady) console.warn('Go API not ready — dashboard may not load');

  createWindow();
  createTray();
  monitorSSE();
});

app.on('before-quit', () => {
  stopAll();
});

app.on('window-all-closed', () => {
  app.quit();
});

app.on('activate', () => {
  if (mainWindow === null) createWindow();
  else mainWindow.show();
});
