# TRAKSHYA WAF — Windows launcher
# Usage: irm https://raw.githubusercontent.com/Pradyu12/TRAKSHYA-WAF/main/landing/start.ps1 | iex
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

$base = "https://raw.githubusercontent.com/Pradyu12/TRAKSHYA-WAF/main"

# Check if we're already in the repo
if ((Test-Path "server.js") -and (Test-Path "frontend")) {
  $repoDir = (Get-Location).Path
  Write-Host "  * Using local repo: $repoDir" -ForegroundColor Cyan
} else {
  $repoDir = Join-Path $env:TEMP "trakshya-waf-$([guid]::NewGuid().ToString('N').Substring(0,8))"
  Write-Host "  * Downloading TRAKSHYA WAF to $repoDir..." -ForegroundColor Cyan

  $frontendDir = Join-Path $repoDir "frontend"
  $staticDir = Join-Path $frontendDir "static"
  New-Item -ItemType Directory -Path $staticDir -Force | Out-Null

  Write-Host "  * Downloading server.js..." -ForegroundColor Cyan
  Invoke-WebRequest "$base/server.js" -OutFile (Join-Path $repoDir "server.js") -UseBasicParsing

  Write-Host "  * Downloading dashboard..." -ForegroundColor Cyan
  Invoke-WebRequest "$base/frontend/dashboard.html" -OutFile (Join-Path $frontendDir "dashboard.html") -UseBasicParsing

  Write-Host "  * Downloading globe assets..." -ForegroundColor Cyan
  try { Invoke-WebRequest "$base/frontend/static/earth.glb" -OutFile (Join-Path $staticDir "earth.glb") -UseBasicParsing } catch { Write-Host "  ! globe.glb skipped (optional)" -ForegroundColor DarkYellow }
  try { Invoke-WebRequest "$base/frontend/static/earth.jpg" -OutFile (Join-Path $staticDir "earth.jpg") -UseBasicParsing } catch { Write-Host "  ! globe.jpg skipped (optional)" -ForegroundColor DarkYellow }
}

Set-Location $repoDir

# Start server
$port = if ($env:TRAKSHYA_PORT) { $env:TRAKSHYA_PORT } else { "8000" }
Write-Host "  v Dashboard:  http://localhost:$port" -ForegroundColor Green
Write-Host "  v Proxy:      http://localhost:8080" -ForegroundColor Green
Write-Host "  v SSE Stream:  http://localhost:$port/api/stream" -ForegroundColor Green
Write-Host "`n  Press Ctrl+C to stop.`n"

node server.js
