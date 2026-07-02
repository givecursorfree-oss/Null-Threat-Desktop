# CI-only: downloads ClamAV Windows ZIP and bundles binaries + virus DB.
# Usage: .\scripts\setup-clamav-ci.ps1

$ErrorActionPreference = "Stop"

$Version = "1.5.2"
$Arch = "x64"
$ZipName = "clamav-$Version.win.$Arch.zip"
$Url = "https://www.clamav.net/downloads/production/$ZipName"
$ZipPath = Join-Path $env:RUNNER_TEMP $ZipName

if (-not $env:RUNNER_TEMP) {
    $ZipPath = Join-Path ([System.IO.Path]::GetTempPath()) $ZipName
}

Write-Host "Downloading ClamAV $Version for Windows ($Arch)..."
Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $ScriptDir "setup-clamav.ps1") -ZipPath $ZipPath -AllowArchMismatch
