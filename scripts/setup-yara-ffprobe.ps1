# Bundles YARA, ffprobe, ffmpeg, and exiftool for Windows into src-tauri/binaries/windows
# Usage: .\scripts\setup-yara-ffprobe.ps1

$ErrorActionPreference = "Stop"

$YaraVersion = "4.5.2"
$YaraBuild = "2326"
$ExifToolVersion = "13.59"
$FfmpegUrl = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip"
$ExifToolUrl = "https://downloads.sourceforge.net/project/exiftool/exiftool-${ExifToolVersion}_64.zip"

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

Write-Host "Downloading FFmpeg (ffmpeg + ffprobe) for Windows x64..."
$FfmpegZip = Join-Path $TempDir "ffmpeg-win64.zip"
Invoke-WebRequest -Uri $FfmpegUrl -OutFile $FfmpegZip -UseBasicParsing

$FfmpegExtract = Join-Path $TempDir "ffmpeg"
if (Test-Path $FfmpegExtract) { Remove-Item -Recurse -Force $FfmpegExtract }
Expand-Archive -Path $FfmpegZip -DestinationPath $FfmpegExtract -Force

$FfmpegBinDir = Get-ChildItem -Path $FfmpegExtract -Recurse -Directory -Filter "bin" | Select-Object -First 1
if (-not $FfmpegBinDir) { throw "ffmpeg bin directory not found in archive" }

foreach ($tool in @("ffmpeg.exe", "ffprobe.exe")) {
    $src = Join-Path $FfmpegBinDir.FullName $tool
    if (-not (Test-Path $src)) { throw "$tool not found in FFmpeg archive" }
    Copy-Item -Force $src (Join-Path $BinDir $tool)
}

Get-ChildItem -Path $FfmpegBinDir.FullName -Filter "*.dll" | ForEach-Object {
    Copy-Item -Force $_.FullName (Join-Path $BinDir $_.Name)
}

Write-Host "Downloading ExifTool $ExifToolVersion for Windows..."
$ExifZip = Join-Path $TempDir "exiftool-win.zip"
# SourceForge mirrors require redirect following; curl handles this reliably on Windows.
curl.exe -fsSL -o $ExifZip $ExifToolUrl
if ($LASTEXITCODE -ne 0) { throw "ExifTool download failed (curl exit $LASTEXITCODE)" }
$zipBytes = [System.IO.File]::ReadAllBytes($ExifZip)
if ($zipBytes.Length -lt 2 -or $zipBytes[0] -ne 0x50 -or $zipBytes[1] -ne 0x4B) {
    throw "ExifTool download did not return a valid zip archive"
}

$ExifExtract = Join-Path $TempDir "exiftool"
if (Test-Path $ExifExtract) { Remove-Item -Recurse -Force $ExifExtract }
Expand-Archive -Path $ExifZip -DestinationPath $ExifExtract -Force

$ExifExe = Get-ChildItem -Path $ExifExtract -Recurse -Filter "exiftool(-k).exe" | Select-Object -First 1
if (-not $ExifExe) {
    $ExifExe = Get-ChildItem -Path $ExifExtract -Recurse -Filter "exiftool*.exe" | Select-Object -First 1
}
if (-not $ExifExe) { throw "exiftool executable not found in ExifTool archive" }

Copy-Item -Force $ExifExe.FullName (Join-Path $BinDir "exiftool.exe")

$ExifFilesDir = Get-ChildItem -Path $ExifExtract -Recurse -Directory -Filter "exiftool_files" | Select-Object -First 1
if ($ExifFilesDir) {
    $DestExifFiles = Join-Path $BinDir "exiftool_files"
    if (Test-Path $DestExifFiles) { Remove-Item -Recurse -Force $DestExifFiles }
    Copy-Item -Recurse -Force $ExifFilesDir.FullName $DestExifFiles
} else {
    Write-Warning "exiftool_files directory not found — exiftool may fail at runtime"
}

Write-Host "Verifying bundled tools..."
& (Join-Path $BinDir "yara.exe") --version
& (Join-Path $BinDir "ffprobe.exe") -version
& (Join-Path $BinDir "ffmpeg.exe") -version
& (Join-Path $BinDir "exiftool.exe") -ver

Write-Host "Windows scanner tools ready in $BinDir"
