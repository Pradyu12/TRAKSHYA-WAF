const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('trakshya', {
  getBackendStatus: () => ipcRenderer.invoke('get-backend-status'),
  restartBackend: (name) => ipcRenderer.invoke('restart-backend', name),
  onNotification: (callback) => ipcRenderer.on('notification', (_e, d) => callback(d)),
  quit: () => ipcRenderer.send('quit'),
  minimizeToTray: () => ipcRenderer.send('minimize-to-tray'),
  getAutoLaunch: () => ipcRenderer.invoke('get-auto-launch'),
  setAutoLaunch: (enabled) => ipcRenderer.invoke('set-auto-launch', enabled),
  getVersion: () => ipcRenderer.invoke('get-version'),
});
