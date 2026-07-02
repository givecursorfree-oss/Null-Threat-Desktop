# Downloads bundled background assets for Null Threat (offline-capable pieces only).
# Run from repo root: .\shieldscan\scripts\download-background-assets.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$vendorDir = Join-Path $root "public\vendor"
$backgroundDir = Join-Path $root "public\background"

New-Item -ItemType Directory -Force -Path $vendorDir | Out-Null
New-Item -ItemType Directory -Force -Path $backgroundDir | Out-Null

$sdkUrl = "https://cdn.jsdelivr.net/gh/hiunicornstudio/unicornstudio.js@v1.4.29/dist/unicornStudio.umd.js"
$sdkPath = Join-Path $vendorDir "unicornStudio.umd.js"

Write-Host "Downloading UnicornStudio SDK..."
Invoke-WebRequest -Uri $sdkUrl -OutFile $sdkPath -UseBasicParsing
Write-Host "Saved: $sdkPath"

Write-Host ""
Write-Host "Offline notes:"
Write-Host "  - Local mesh background is built into the app (no download needed)."
Write-Host "  - UnicornStudio SDK is bundled in public/vendor/."
Write-Host "  - Unicorn scene JSON cannot be downloaded automatically."
Write-Host "    Export from Unicorn Studio (Legend plan) and save as:"
Write-Host "    public/background/unicorn-project.json"
Write-Host "  - Spline scene cannot be downloaded from the public embed URL."
Write-Host "    Export Self-Hosted from Spline and save as:"
Write-Host "    public/background/scene.splinecode"
Write-Host ""
Write-Host "Done."
