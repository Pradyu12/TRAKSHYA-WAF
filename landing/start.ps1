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

Show-Spinner "Checking Docker..." 2500

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "`r  X Docker NOT FOUND                              " -ForegroundColor Red
    Write-Host "    Install: https://docs.docker.com/get-docker/"
    exit 1
}

$dockerVer = docker --version 2>$null
Write-Host "`r  [OK] Docker                                    " -ForegroundColor Green

Show-Spinner "Checking Docker Compose..." 2500

try {
    docker compose version 2>$null | Out-Null
    Write-Host "`r  [OK] Docker Compose                             " -ForegroundColor Green
} catch {
    Write-Host "`r  X Docker Compose NOT FOUND                     " -ForegroundColor Red
    Write-Host "    Install: https://docs.docker.com/compose/install/"
    exit 1
}

Start-Sleep -Milliseconds 300

# ── Clone phase ─────────────────────────────────────────
Write-Host ""
Write-Host "  ── ACQUISITION ──────────────────────────────────────────" -ForegroundColor Green

if ((Test-Path "docker-compose.stack.yml") -and (Test-Path "frontend")) {
    $repoDir = (Get-Location).Path
    Write-Host "  [*] Local repo detected: $repoDir" -ForegroundColor Cyan
} else {
    $repoDir = Join-Path $env:TEMP "trakshya-waf-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $repoDir -Force | Out-Null

    Write-Host "  [*] Cloning TRAKSHYA-WAF..." -ForegroundColor Cyan
    Show-Spinner "Cloning repository..." 3000
    git clone --depth 1 https://github.com/Pradyu12/TRAKSHYA-WAF.git $repoDir 2>$null
    Write-Host "  [OK] Repository cloned" -ForegroundColor Green
}

Set-Location $repoDir

# ── Build & Launch ──────────────────────────────────────
Write-Host ""
Write-Host "  ── BUILDING CONTAINERS ──────────────────────────────────" -ForegroundColor Green

docker compose -f docker-compose.stack.yml up --build -d 2>&1 | Out-Null
Write-Host "  [OK] Containers built and started" -ForegroundColor Green

# ── Wait for health ─────────────────────────────────────
Write-Host ""
Write-Host "  ── HEALTH CHECK ────────────────────────────────────────" -ForegroundColor Green

$maxWait = 60
$waited = 0
$healthy = $false

while ($waited -lt $maxWait) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200) {
            Write-Host "  [OK] API is healthy" -ForegroundColor Green
            $healthy = $true
            break
        }
    } catch {}
    Show-Spinner "Waiting for API..." 2000
    $waited += 2
}

if (-not $healthy) {
    Write-Host "`r  X API failed to start within ${maxWait}s          " -ForegroundColor Red
    Write-Host "    Check logs: docker compose -f docker-compose.stack.yml logs"
    exit 1
}

# ── System Ready ────────────────────────────────────────
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

# ── Follow logs ─────────────────────────────────────────
try {
    docker compose -f docker-compose.stack.yml logs -f --tail=50
} finally {
    Write-Host "`n  Shutting down..." -ForegroundColor DarkGray
    docker compose -f docker-compose.stack.yml down 2>$null
}
