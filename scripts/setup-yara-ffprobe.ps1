# Bundles YARA + ffprobe for Windows into src-tauri/binaries/windows
# Usage: .\scripts\setup-yara-ffprobe.ps1

$ErrorActionPreference = "Stop"

$YaraVersion = "4.5.2"
$YaraBuild = "2326"
$FfmpegUrl = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
$BinDir = Join-Path $Root "src-tauri\binaries\windows"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "null-threat-tools-setup"

New-Item -ItemType Directory -Force -Path $BinDir, $TempDir | Out-Null

function Get-YaraZipUrl {
    param([string]$Version, [string]$Build)
    "https://github.com/VirusTotal/yara/releases/download/v$Version/yara-v$Version-$Build-win64.zip"
}

Write-Host "Downloading YARA $YaraVersion for Windows x64..."
$YaraZip = Join-Path $TempDir "yara-win64.zip"
$YaraUrl = Get-YaraZipUrl -Version $YaraVersion -Build $YaraBuild
Invoke-WebRequest -Uri $YaraUrl -OutFile $YaraZip -UseBasicParsing

$YaraExtract = Join-Path $TempDir "yara"
if (Test-Path $YaraExtract) { Remove-Item -Recurse -Force $YaraExtract }
Expand-Archive -Path $YaraZip -DestinationPath $YaraExtract -Force

$YaraExe = Get-ChildItem -Path $YaraExtract -Recurse -Filter "yara64.exe" | Select-Object -First 1
if (-not $YaraExe) {
    $YaraExe = Get-ChildItem -Path $YaraExtract -Recurse -Filter "yara.exe" | Select-Object -First 1
}
if (-not $YaraExe) { throw "yara executable not found in YARA archive" }

Copy-Item -Force $YaraExe.FullName (Join-Path $BinDir "yara.exe")
Get-ChildItem -Path $YaraExe.DirectoryName -Filter "*.dll" | ForEach-Object {
    Copy-Item -Force $_.FullName (Join-Path $BinDir $_.Name)
}

Write-Host "Downloading FFmpeg (ffprobe) for Windows x64..."
$FfmpegZip = Join-Path $TempDir "ffmpeg-win64.zip"
Invoke-WebRequest -Uri $FfmpegUrl -OutFile $FfmpegZip -UseBasicParsing

$FfmpegExtract = Join-Path $TempDir "ffmpeg"
if (Test-Path $FfmpegExtract) { Remove-Item -Recurse -Force $FfmpegExtract }
Expand-Archive -Path $FfmpegZip -DestinationPath $FfmpegExtract -Force

$FfprobeExe = Get-ChildItem -Path $FfmpegExtract -Recurse -Filter "ffprobe.exe" | Select-Object -First 1
if (-not $FfprobeExe) { throw "ffprobe.exe not found in FFmpeg archive" }

Copy-Item -Force $FfprobeExe.FullName (Join-Path $BinDir "ffprobe.exe")
Get-ChildItem -Path $FfprobeExe.DirectoryName -Filter "*.dll" | ForEach-Object {
    Copy-Item -Force $_.FullName (Join-Path $BinDir $_.Name)
}

Write-Host "Verifying bundled tools..."
& (Join-Path $BinDir "yara.exe") --version
& (Join-Path $BinDir "ffprobe.exe") -version

Write-Host "Windows YARA + ffprobe ready in $BinDir"
