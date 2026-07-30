# Register TRAKSHYA WAF for Windows autostart
$vbsPath = (Resolve-Path "$PSScriptRoot\autostart.vbs").Path
if (-not (Test-Path $vbsPath)) {
    Write-Error "VBS file not found: $vbsPath"
    exit 1
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "trakshya-waf" -Value $vbsPath -ErrorAction Stop
Write-Host "Autostart registered successfully!"
Write-Host "VBS path: $vbsPath"
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "trakshya-waf" | Format-List trakshya-waf
