# TRAKSHYA WAF — Windows launcher
# Usage: irm https://raw.githubusercontent.com/Pradyu12/TRAKSHYA-WAF/main/landing/start.ps1 | iex
$ErrorActionPreference = 'Stop'

function Show-Spinner {
    param([string]$Message, [int]$DurationMs = 2000)
    $chars = @('⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏')
    $end = [DateTime]::Now.AddMilliseconds($DurationMs)
    $i = 0
    while ([DateTime]::Now -lt $end) {
        Write-Host "`r  $($chars[$i % 10]) $Message" -NoNewline -ForegroundColor Cyan
        Start-Sleep -Milliseconds 80
        $i++
    }
    Write-Host "`r                                            " -NoNewline
}

function Show-Progress {
    param([string]$Label, [int]$Width = 30)
    Write-Host ""
    for ($i = 0; $i -le $Width; $i++) {
        $pct = [math]::Floor($i * 100 / $Width)
        $filled = '█' * $i
        $empty = '░' * ($Width - $i)
        Write-Host "`r  $('{0,-20}' -f $Label) [$filled$empty] $pct%" -NoNewline -ForegroundColor Green
        Start-Sleep -Milliseconds 30
    }
    Write-Host ""
}

function Type-Line {
    param([string]$Text, [int]$DelayMs = 20)
    Write-Host "  > " -NoNewline -ForegroundColor DarkGreen
    foreach ($c in $Text.ToCharArray()) {
        Write-Host $c -NoNewline -ForegroundColor DarkGreen
        Start-Sleep -Milliseconds $DelayMs
    }
    Write-Host ""
}

# ── Banner ──────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "       ████████╗██╗  ██╗██╗   ██╗██╗     ██╗  ██╗██╗   ██╗███████╗" -ForegroundColor Green
Write-Host "       ╚══██╔══╝██║  ██║██║   ██║██║     ██║  ██║██║   ██║██╔════╝" -ForegroundColor Green
Write-Host "          ██║   ███████║██║   ██║██║     ███████║██║   ██║███████╗" -ForegroundColor Green
Write-Host "          ██║   ██╔══██║██║   ██║██║     ██╔══██║██║   ██║╚════██║" -ForegroundColor Green
Write-Host "          ██║   ██║  ██║╚██████╔╝███████╗██║  ██║╚██████╔╝███████║" -ForegroundColor Green
Write-Host "          ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝" -ForegroundColor Green
Write-Host "                          WAF v2.0 — Divine Eagle Guardian" -ForegroundColor DarkGreen
Write-Host ""

# ── Boot sequence ───────────────────────────────────────
Start-Sleep -Milliseconds 300
Type-Line "[INITIALIZING DEFENSE SYSTEMS...]"
Start-Sleep -Milliseconds 200
Type-Line "[LOADING THREAT SIGNATURES...]"
Start-Sleep -Milliseconds 200
Type-Line "[ESTABLISHING SECURE CHANNEL...]"
Start-Sleep -Milliseconds 400

# ── Dependency checks ───────────────────────────────────
Write-Host ""
Write-Host "  ── DEPENDENCY CHECK ─────────────────────────────────────" -ForegroundColor Green

Show-Spinner "Checking Node.js..." 2500

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "`r  X Node.js NOT FOUND                          " -ForegroundColor Red
    Write-Host "    Install: winget install OpenJS.NodeJS.LTS"
    Write-Host "    Or visit: https://nodejs.org/"
    exit 1
}

$nodeVer = node -v 2>$null
Write-Host "`r  [OK] Node.js $nodeVer                         " -ForegroundColor Green

Show-Spinner "Checking PowerShell..." 1500
Write-Host "`r  [OK] PowerShell $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)                       " -ForegroundColor Green
Start-Sleep -Milliseconds 300

# ── Download phase ──────────────────────────────────────
Write-Host ""
Write-Host "  ── ACQUISITION ──────────────────────────────────────────" -ForegroundColor Green

$base = "https://raw.githubusercontent.com/Pradyu12/TRAKSHYA-WAF/main"

if ((Test-Path "server.js") -and (Test-Path "frontend")) {
    $repoDir = (Get-Location).Path
    Write-Host "  [*] Local repo detected: $repoDir" -ForegroundColor Cyan
} else {
    $repoDir = Join-Path $env:TEMP "trakshya-waf-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    $frontendDir = Join-Path $repoDir "frontend"
    $staticDir = Join-Path $frontendDir "static"
    New-Item -ItemType Directory -Path $staticDir -Force | Out-Null

    Write-Host "  [*] Target: $repoDir" -ForegroundColor Cyan
    Write-Host ""

    Show-Progress "server.js"
    Invoke-WebRequest "$base/server.js" -OutFile (Join-Path $repoDir "server.js") -UseBasicParsing

    Show-Progress "dashboard.html"
    Invoke-WebRequest "$base/frontend/dashboard.html" -OutFile (Join-Path $frontendDir "dashboard.html") -UseBasicParsing

    Write-Host "  [*] Fetching globe assets..." -ForegroundColor Cyan
    try { Invoke-WebRequest "$base/frontend/static/earth.glb" -OutFile (Join-Path $staticDir "earth.glb") -UseBasicParsing } catch { Write-Host "  ! globe.glb skipped (optional)" -ForegroundColor DarkYellow }
    try { Invoke-WebRequest "$base/frontend/static/earth.jpg" -OutFile (Join-Path $staticDir "earth.jpg") -UseBasicParsing } catch { Write-Host "  ! globe.jpg skipped (optional)" -ForegroundColor DarkYellow }

    Write-Host "  [OK] All files acquired" -ForegroundColor Green
}

Set-Location $repoDir

# ── Launch ──────────────────────────────────────────────
$port = if ($env:TRAKSHYA_PORT) { $env:TRAKSHYA_PORT } else { "8000" }
Write-Host ""
Write-Host "  ── SYSTEM READY ─────────────────────────────────────────" -ForegroundColor Green
Write-Host ""
Write-Host "  ┌────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │                                                        │" -ForegroundColor Cyan
Write-Host "  │  Dashboard:    http://localhost:$port$(' ' * (33 - $port.Length))│" -ForegroundColor Cyan
Write-Host "  │  Proxy:        http://localhost:8080                    │" -ForegroundColor Cyan
Write-Host "  │  SSE Stream:   http://localhost:$port/api/stream$(' ' * (22 - $port.Length))│" -ForegroundColor Cyan
Write-Host "  │                                                        │" -ForegroundColor Cyan
Write-Host "  └────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Press Ctrl+C to terminate." -ForegroundColor DarkGray
Write-Host ""

node server.js
