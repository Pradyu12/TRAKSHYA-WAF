# TRAKSHYA WAF — Windows installer/controller
# Requires PowerShell 5.1+ (Windows 10/11)
[CmdletBinding()]
param(
  [Parameter(Position=0)]
  [ValidateSet('install','uninstall','start','stop','restart','status','logs','doctor','help')]
  [string]$Command = 'help',

  [ValidateSet('local','service')]
  [string]$Mode = 'local',

  [string]$ServiceUser = 'trakshya',
  [int]$DashboardPort = 8000,
  [int]$ProxyPort = 8080,
  [int]$ApiPort = 8001,

  [string]$LogService
)

$ErrorActionPreference = 'Stop'

$RepoRoot = if ((Get-Item .).FullName -match 'Cargo\.toml|\\rust\\') { (Get-Location).Path } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$InstallDir = 'C:\trakshya-waf'
$BinDir = 'C:\trakshya-waf\bin'
$DataDir = 'C:\trakshya-waf\data'
$LogDir = 'C:\trakshya-waf\logs'
$ServiceName = 'trakshya-waf'

$Colors = @{
  Red = '`e[31m'
  Green = '`e[32m'
  Cyan = '`e[36m'
  Yellow = '`e[33m'
  Reset = '`e[0m'
}

function Write-Color([string]$Text, [string]$Color = 'Reset') {
  Write-Host "$($Colors[$Color])$Text$($Colors['Reset'])"
}

function Write-Usage {
  Write-Host @"
TRAKSHYA WAF — Windows Installer

Usage:
  trakshya-install.ps1 <command> [options]

Commands:
  install [--mode=local|service]   Install the firewall
  uninstall                        Remove services and files
  start                            Start services
  stop                             Stop services
  restart                          Restart services
  status                           Show service status
  logs [service]                   Tail logs
  doctor                           Diagnostics
  help                             Show this help

Options:
  --mode              local or service (default: local)
  --service-user      Windows service user (default: LocalSystem for service mode)
  --dashboard-port    Dashboard port (default: 8000)
  --proxy-port        Proxy port (default: 8080)
  --api-port          API port (default: 8001)
  --logs              Service name for logs (trakshya-dashboard, trakshya-proxy, trakshya-api)

Examples:
  .\trakshya-install.ps1 install --mode=local
  .\trakshya-install.ps1 install --mode=service
  .\trakshya-install.ps1 status
  .\trakshya-install.ps1 logs trakshya-dashboard
"@
}

function Test-Command([string]$Name) {
  try { Get-Command $Name -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function Install-Dependencies {
  Write-Color 'Checking dependencies...' 'Cyan'

  $missing = @()
  if (-not (Test-Command 'node')) { $missing += 'Node.js 18+ (https://nodejs.org/)' }
  if (-not (Test-Command 'npm')) { $missing += 'npm (comes with Node.js)' }
  if (-not (Test-Command 'cargo')) { $missing += 'Rust/cargo (https://rustup.rs/)' }
  if (-not (Test-Command 'go')) { $missing += 'Go 1.23+ (https://go.dev/dl/)' }

  if ($missing.Count -gt 0) {
    Write-Color 'Missing dependencies:' 'Yellow'
    $missing | ForEach-Object { Write-Host "  - $_" }
    Write-Color 'Install them first, then re-run this script.' 'Yellow'
    throw 'Missing dependencies'
  }

  Write-Color 'Dependencies OK.' 'Green'
}

function New-Directory([string]$Path) {
  if (-not (Test-Path $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Copy-Items {
  param([string]$Source, [string]$Dest)
  if (Test-Path $Source) {
    Copy-Item -Path $Source -Destination $Dest -Recurse -Force
  }
}

function Install-Local {
  Write-Color 'Installing TRAKSHYA WAF (local mode)...' 'Green'

  New-Directory $InstallDir
  New-Directory $BinDir
  New-Directory $DataDir
  New-Directory $LogDir

  Write-Color 'Copying files...' 'Cyan'
  Copy-Items ($RepoRoot) $InstallDir

  # Install Node dependencies
  if (Test-Path (Join-Path $InstallDir 'package.json')) {
    Push-Location $InstallDir
    try {
      npm install --no-audit --no-fund | Out-Null
    } catch {
      Write-Color "npm install failed: $_" 'Yellow'
    }
    Pop-Location
  }

  # Build Rust binary
  $rustBin = Join-Path $RepoRoot 'rust\target\release\trakshya-proxy.exe'
  if (-not (Test-Path $rustBin)) {
    Write-Color 'Building Rust proxy...' 'Cyan'
    Push-Location (Join-Path $RepoRoot 'rust')
    try {
      cargo build --release 2>&1 | ForEach-Object { Write-Host $_ }
    } catch {
      Write-Color "Rust build failed: $_" 'Yellow'
    }
    Pop-Location
  }

  if (Test-Path $rustBin) {
    Copy-Item $rustBin (Join-Path $BinDir 'trakshya-proxy.exe') -Force
  }

  # Build Go binary
  $goBin = Join-Path $RepoRoot 'go\trakshya-api.exe'
  if (-not (Test-Path $goBin)) {
    Write-Color 'Building Go API...' 'Cyan'
    Push-Location (Join-Path $RepoRoot 'go')
    try {
      $env:CGO_ENABLED = '1'
      go build -o (Join-Path $InstallDir 'bin\trakshya-api.exe') .\cmd\trakshya-api\ 2>&1 | ForEach-Object { Write-Host $_ }
    } catch {
      Write-Color "Go build failed: $_" 'Yellow'
    }
    Pop-Location
  } elseif (-not (Test-Path (Join-Path $InstallDir 'bin\trakshya-api.exe'))) {
    Copy-Item $goBin (Join-Path $InstallDir 'bin\trakshya-api.exe') -Force
  }

  # Generate launcher
  $launcher = @"
@echo off
setlocal
cd /d "$InstallDir"
echo Starting TRAKSHYA WAF...
if exist "$RepoRoot\scripts\trakshya-ascii.sh" bash "$RepoRoot\scripts\trakshya-ascii.sh" 2>nul || true
set RUST_BIN=$InstallDir\bin\trakshya-proxy.exe
set DASHBOARD_PORT=$DashboardPort
set PROXY_PORT=$ProxyPort

if exist "%RUST_BIN%" (
  echo [proxy] http://localhost:%PROXY_PORT%
  start "TRAKSHYA Proxy" /B "%RUST_BIN%" --port %PROXY_PORT%
)

if exist "server.js" (
  echo [dashboard] http://localhost:%DASHBOARD_PORT%
  node server.js
) else (
  echo Node.js not found or server.js missing.
  pause
  exit /b 1
)
"@

  $launcherPath = Join-Path $BinDir 'trakshya-waf.cmd'
  Set-Content -Path $launcherPath -Value $launcher -Encoding ASCII

  # Create Start Menu shortcut
  $WshShell = New-Object -comObject WScript.Shell
  $StartMenu = [Environment]::GetFolderPath('CommonStartMenu')
  $Shortcut = $WshShell.CreateShortcut((Join-Path $StartMenu 'TRAKSHYA WAF.lnk'))
  $Shortcut.TargetPath = $launcherPath
  $Shortcut.WorkingDirectory = $InstallDir
  $Shortcut.Save()

  Write-Color "Installed: $launcherPath" 'Green'
  Write-Color "Start Menu shortcut created." 'Green'
  Write-Color "Dashboard: http://localhost:$DashboardPort" 'Green'
  if (Test-Path $rustBin) { Write-Color "Proxy: http://localhost:$ProxyPort" 'Green' }
  Write-Color "API: http://localhost:$ApiPort" 'Green'
}

function Get-Nssm {
  param([string]$InstallDir)
  $nssm = Join-Path $InstallDir 'bin\nssm.exe'
  if (-not (Test-Path $nssm)) {
    # Download nssm if not present
    $url = 'https://nssm.cc/release/nssm-2.24.zip'
    $zip = Join-Path $InstallDir 'bin\nssm.zip'
    Write-Color 'Downloading NSSM for Windows service support...' 'Cyan'
    try {
      Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
      Expand-Archive -Path $zip -DestinationPath (Join-Path $InstallDir 'bin') -Force
      $nssm = Get-ChildItem (Join-Path $InstallDir 'bin\nssm*') -Filter 'nssm.exe' -Recurse | Select-Object -First 1 -ExpandProperty FullName
    } catch {
      Write-Color "Failed to download NSSM: $_" 'Yellow'
      return $null
    }
  }
  return $nssm
}

function Install-Service {
  Write-Color 'Installing TRAKSHYA WAF (Windows service mode)...' 'Green'

  if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Service mode requires Administrator. Run PowerShell as Administrator.'
  }

  New-Directory $InstallDir
  New-Directory $BinDir
  New-Directory $DataDir
  New-Directory $LogDir

  Write-Color 'Copying files...' 'Cyan'
  Copy-Items ($RepoRoot) $InstallDir

  # Install Node dependencies
  if (Test-Path (Join-Path $InstallDir 'package.json')) {
    Push-Location $InstallDir
    try { npm install --no-audit --no-fund | Out-Null } catch { Write-Color "npm install failed: $_" 'Yellow' }
    Pop-Location
  }

  # Build binaries
  $rustBin = Join-Path $RepoRoot 'rust\target\release\trakshya-proxy.exe'
  if (-not (Test-Path $rustBin)) {
    Write-Color 'Building Rust proxy...' 'Cyan'
    Push-Location (Join-Path $RepoRoot 'rust')
    try { cargo build --release 2>&1 | ForEach-Object { Write-Host $_ } } catch { Write-Color "Rust build failed: $_" 'Yellow' }
    Pop-Location
  }
  if (Test-Path $rustBin) { Copy-Item $rustBin (Join-Path $BinDir 'trakshya-proxy.exe') -Force }

  $goBin = Join-Path $RepoRoot 'go\trakshya-api.exe'
  if (-not (Test-Path $goBin)) {
    Write-Color 'Building Go API...' 'Cyan'
    Push-Location (Join-Path $RepoRoot 'go')
    try {
      $env:CGO_ENABLED = '1'
      go build -o (Join-Path $InstallDir 'bin\trakshya-api.exe') .\cmd\trakshya-api\ 2>&1 | ForEach-Object { Write-Host $_ }
    } catch { Write-Color "Go build failed: $_" 'Yellow' }
    Pop-Location
  }
  if (Test-Path $goBin) { Copy-Item $goBin (Join-Path $InstallDir 'bin\trakshya-api.exe') -Force }

  # Install NSSM
  $nssm = Get-Nssm -InstallDir $InstallDir
  if (-not $nssm) {
    throw 'NSSM is required for service mode. Install it from https://nssm.cc/ and re-run.'
  }

  Write-Color "Using NSSM: $nssm" 'Cyan'

  # Install services
  $nodePath = (Get-Command node).Source
  $nodeServer = Join-Path $InstallDir 'server.js'

  if (-not (Test-Path $nodeServer)) { throw "Missing $nodeServer" }

  # Dashboard service
  & $nssm install $ServiceName-dashboard $nodePath "`"$nodeServer`""
  & $nssm set $ServiceName-dashboard AppDirectory $InstallDir
  & $nssm set $ServiceName-dashboard DisplayName 'TRAKSHYA WAF Dashboard'
  & $nssm set $ServiceName-dashboard Start SERVICE_AUTO_START
  & $nssm set $ServiceName-dashboard AppStdout (Join-Path $LogDir 'dashboard.log')
  & $nssm set $ServiceName-dashboard AppStderr (Join-Path $LogDir 'dashboard-error.log')

  # Proxy service
  $proxyExe = Join-Path $BinDir 'trakshya-proxy.exe'
  if (Test-Path $proxyExe) {
    & $nssm install $ServiceName-proxy $proxyExe "--port $ProxyPort"
    & $nssm set $ServiceName-proxy AppDirectory $InstallDir
    & $nssm set $ServiceName-proxy DisplayName 'TRAKSHYA WAF Proxy'
    & $nssm set $ServiceName-proxy Start SERVICE_AUTO_START
    & $nssm set $ServiceName-proxy AppStdout (Join-Path $LogDir 'proxy.log')
    & $nssm set $ServiceName-proxy AppStderr (Join-Path $LogDir 'proxy-error.log')
  }

  # API service
  $apiExe = Join-Path $BinDir 'trakshya-api.exe'
  if (Test-Path $apiExe) {
    & $nssm install $ServiceName-api $apiExe
    & $nssm set $ServiceName-api AppDirectory $InstallDir
    & $nssm set $ServiceName-api DisplayName 'TRAKSHYA WAF API'
    & $nssm set $ServiceName-api Start SERVICE_AUTO_START
    & $nssm set $ServiceName-api AppStdout (Join-Path $LogDir 'api.log')
    & $nssm set $ServiceName-api AppStderr (Join-Path $LogDir 'api-error.log')
  }

  Write-Color 'Starting services...' 'Cyan'
  Start-Service -Name "$ServiceName-dashboard" -ErrorAction SilentlyContinue
  if (Test-Path $proxyExe) { Start-Service -Name "$ServiceName-proxy" -ErrorAction SilentlyContinue }
  if (Test-Path $apiExe) { Start-Service -Name "$ServiceName-api" -ErrorAction SilentlyContinue }

  Start-Sleep -Seconds 2
  Show-ServiceStatus
}

function Uninstall-Service {
  if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Uninstall requires Administrator. Run PowerShell as Administrator.'
  }

  Write-Color 'Stopping services...' 'Yellow'
  Get-Service -Name "$ServiceName-*" -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue

  $nssm = Join-Path $InstallDir 'bin\nssm.exe'
  if (-not (Test-Path $nssm)) {
    $nssm = Get-ChildItem (Join-Path $InstallDir 'bin\nssm*') -Filter 'nssm.exe' -Recurse | Select-Object -First 1 -ExpandProperty FullName
  }

  if ($nssm) {
    Get-Service -Name "$ServiceName-*" -ErrorAction SilentlyContinue | ForEach-Object {
      & $nssm stop $_.Name | Out-Null
      & $nssm remove $_.Name confirm | Out-Null
    }
  }

  if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Color "Removed $InstallDir" 'Green'
  }

  # Remove Start Menu shortcut
  $StartMenu = [Environment]::GetFolderPath('CommonStartMenu')
  $shortcut = Join-Path $StartMenu 'TRAKSHYA WAF.lnk'
  if (Test-Path $shortcut) { Remove-Item $shortcut -Force }

  Write-Color 'Uninstall complete.' 'Green'
}

function Start-Services {
  Get-Service -Name "$ServiceName-*" -ErrorAction SilentlyContinue | Start-Service
  Start-Sleep -Seconds 1
  Show-ServiceStatus
}

function Stop-Services {
  Get-Service -Name "$ServiceName-*" -ErrorAction SilentlyContinue | Stop-Service -Force
}

function Show-ServiceStatus {
  Get-Service -Name "$ServiceName-*" -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType
}

function Show-Logs {
  $svc = if ($LogService) { "$ServiceName-$LogService" } else { "$ServiceName-dashboard" }
  $logFile = Join-Path $LogDir "$($LogService -replace 'trakshya-','').log"
  if (-not (Test-Path $logFile)) {
    $services = Get-Service -Name "$ServiceName-*" -ErrorAction SilentlyContinue
    foreach ($s in $services) {
      $name = $s.Name -replace [regex]::Escape("$ServiceName-"), ''
      $candidate = Join-Path $LogDir "$name.log"
      if (Test-Path $candidate) { $logFile = $candidate; break }
    }
  }
  if (Test-Path $logFile) {
    Get-Content $logFile -Wait -Tail 50
  } else {
    Write-Color "Logs not found in $LogDir" 'Yellow'
  }
}

function Show-Doctor {
  Write-Color 'TRAKSHYA WAF diagnostics (Windows)' 'Cyan'
  $checks = @(
    @{ Label = 'PowerShell'; Test = { $PSVersionTable.PSVersion } },
    @{ Label = 'Node.js'; Test = { if (Test-Command 'node') { 'present' } else { 'missing' } } },
    @{ Label = 'npm'; Test = { if (Test-Command 'npm') { 'present' } else { 'missing' } } },
    @{ Label = 'cargo'; Test = { if (Test-Command 'cargo') { 'present' } else { 'missing' } } },
    @{ Label = 'go'; Test = { if (Test-Command 'go') { 'present' } else { 'missing' } } },
    @{ Label = 'install dir'; Test = { if (Test-Path $InstallDir) { 'present' } else { 'missing' } } },
    @{ Label = 'proxy binary'; Test = { if (Test-Path (Join-Path $InstallDir 'bin\trakshya-proxy.exe')) { 'present' } else { 'missing' } } },
    @{ Label = 'api binary'; Test = { if (Test-Path (Join-Path $InstallDir 'bin\trakshya-api.exe')) { 'present' } else { 'missing' } } }
  )

  foreach ($c in $checks) {
    $detail = & $c.Test
    $ok = $detail -ne 'missing'
    Write-Host "$(if($ok){$Colors.Green}else{$Colors.Red})$(if($ok){'✔'}else{'✖'})$($Colors['Reset']) $($c.Label): $detail"
  }

  Write-Color 'Diagnostics complete.' 'Cyan'
}

switch ($Command) {
  'install' {
    if ($Mode -eq 'service') { Install-Service } else { Install-Local }
  }
  'uninstall' { Uninstall-Service }
  'start' { Start-Services }
  'stop' { Stop-Services }
  'restart' { Stop-Services; Start-Services }
  'status' { Show-ServiceStatus }
  'logs' { Show-Logs }
  'doctor' { Show-Doctor }
  'help' { Write-Usage }
  default { Write-Usage; exit 1 }
}
