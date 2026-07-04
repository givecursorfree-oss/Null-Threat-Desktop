# One-command setup: ClamAV + YARA + ffprobe for Windows builds
# Usage: .\scripts\setup-scanner-tools.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== Null Threat: bundling scanner tools ==="

if (-not (Test-Path (Join-Path $ScriptDir "..\src-tauri\binaries\windows\clamscan.exe"))) {
  & (Join-Path $ScriptDir "setup-clamav.ps1")
} else {
  Write-Host "ClamAV already bundled - skipping"
}

& (Join-Path $ScriptDir "setup-yara-ffprobe.ps1")

Write-Host ""
Write-Host "All scanner tools bundled. Run: npm run build"
