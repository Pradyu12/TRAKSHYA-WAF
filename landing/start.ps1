# TRAKSHYA WAF — Windows launcher
# Usage: powershell -ExecutionPolicy Bypass -File start.ps1
$ErrorActionPreference = 'Stop'

Write-Host "`n  TRAKSHYA WAF — Starting...`n" -ForegroundColor Magenta

# Check Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Host "  x Node.js is required. Install it:" -ForegroundColor Red
  Write-Host "    winget install OpenJS.NodeJS.LTS"
  Write-Host "  Or visit: https://nodejs.org/"
  exit 1
}

$nodeVer = node -v 2>$null
Write-Host "  v Node.js $nodeVer" -ForegroundColor Green

# Determine repo location
if ((Test-Path ".git") -and (Test-Path "server.js")) {
  $repoDir = (Get-Location).Path
  Write-Host "  * Using local repo: $repoDir" -ForegroundColor Cyan
} else {
  $repoDir = Join-Path $env:TEMP "trakshya-waf-$([guid]::NewGuid().ToString('N').Substring(0,8))"
  Write-Host "  * Cloning to $repoDir..." -ForegroundColor Cyan
  if (Test-Path $repoDir) { Remove-Item $repoDir -Recurse -Force }
  git clone --depth 1 https://github.com/Pradyu12/TRAKSHYA-WAF.git $repoDir 2>$null
}

Set-Location $repoDir

# Start server
$port = if ($env:TRAKSHYA_PORT) { $env:TRAKSHYA_PORT } else { "8000" }
Write-Host "  v Dashboard:  http://localhost:$port" -ForegroundColor Green
Write-Host "  v Proxy:      http://localhost:8080" -ForegroundColor Green
Write-Host "  v SSE Stream:  http://localhost:$port/api/stream" -ForegroundColor Green
Write-Host "`n  Press Ctrl+C to stop.`n"

node server.js
