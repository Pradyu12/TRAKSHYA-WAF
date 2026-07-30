@echo off
REM Used by Windows autostart — launches TRAKSHYA WAF minimized to tray
cd /d "%~dp0"
if not exist "package.json" (
  echo Wrong directory - package.json not found
  exit /b 1
)
if exist "node_modules\.bin\electron.cmd" (
  "node_modules\.bin\electron.cmd" . --hidden
) else (
  npx electron . --hidden
)
