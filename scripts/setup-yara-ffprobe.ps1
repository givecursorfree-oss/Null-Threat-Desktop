# Bundles YARA, ffprobe, ffmpeg, and exiftool for Windows into src-tauri/binaries/windows
# Usage: .\scripts\setup-yara-ffprobe.ps1

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$YaraVersion = "4.5.2"
$YaraBuild = "2326"
$ExifToolVersion = "13.59"
$FfmpegUrl = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip"
$ExifToolUrl = "https://sourceforge.net/projects/exiftool/files/exiftool-${ExifToolVersion}_64.zip/download"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
$BinDir = Join-Path $Root "src-tauri\binaries\windows"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "null-threat-tools-setup"

New-Item -ItemType Directory -Force -Path $BinDir, $TempDir | Out-Null

function Download-File {
    param(
        [string]$Url,
        [string]$Destination,
        [string]$Label
    )
    Write-Host "Downloading $Label..."
    if (Test-Path $Destination) { Remove-Item -Force $Destination }

    # curl is more reliable than Invoke-WebRequest on CI (redirects, large files).
    curl.exe -fSL --retry 3 --retry-delay 2 -o $Destination $Url
    if ($LASTEXITCODE -ne 0) {
        throw "$Label download failed (curl exit $LASTEXITCODE)"
    }

    if (-not (Test-Path $Destination)) {
        throw "$Label download missing: $Destination"
    }

    $size = (Get-Item $Destination).Length
    if ($size -lt 1024) {
        throw "$Label download too small ($size bytes) — likely an HTML error page"
    }
}

function Test-ZipFile {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 4 -or $bytes[0] -ne 0x50 -or $bytes[1] -ne 0x4B) {
        throw "Not a valid zip archive: $Path"
    }
}

function Expand-ZipFile {
    param(
        [string]$ZipPath,
        [string]$Destination
    )
    Test-ZipFile -Path $ZipPath
    if (Test-Path $Destination) { Remove-Item -Recurse -Force $Destination }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $Destination)
}

$YaraZip = Join-Path $TempDir "yara-win64.zip"
$YaraUrl = "https://github.com/VirusTotal/yara/releases/download/v$YaraVersion/yara-v$YaraVersion-$YaraBuild-win64.zip"
Download-File -Url $YaraUrl -Destination $YaraZip -Label "YARA $YaraVersion"

$YaraExtract = Join-Path $TempDir "yara"
Expand-ZipFile -ZipPath $YaraZip -Destination $YaraExtract

$YaraExe = Get-ChildItem -Path $YaraExtract -Recurse -Filter "yara64.exe" | Select-Object -First 1
if (-not $YaraExe) {
    $YaraExe = Get-ChildItem -Path $YaraExtract -Recurse -Filter "yara.exe" | Select-Object -First 1
}
if (-not $YaraExe) { throw "yara executable not found in YARA archive" }

Copy-Item -Force $YaraExe.FullName (Join-Path $BinDir "yara.exe")
Get-ChildItem -Path $YaraExe.DirectoryName -Filter "*.dll" | ForEach-Object {
    Copy-Item -Force $_.FullName (Join-Path $BinDir $_.Name)
}

$FfmpegZip = Join-Path $TempDir "ffmpeg-win64.zip"
Download-File -Url $FfmpegUrl -Destination $FfmpegZip -Label "FFmpeg"

$FfmpegExtract = Join-Path $TempDir "ffmpeg"
Expand-ZipFile -ZipPath $FfmpegZip -Destination $FfmpegExtract

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

$ExifZip = Join-Path $TempDir "exiftool-win.zip"
Download-File -Url $ExifToolUrl -Destination $ExifZip -Label "ExifTool $ExifToolVersion"

$ExifExtract = Join-Path $TempDir "exiftool"
Expand-ZipFile -ZipPath $ExifZip -Destination $ExifExtract

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
if ($LASTEXITCODE -ne 0) { throw "yara verification failed" }

& (Join-Path $BinDir "ffprobe.exe") -version | Select-Object -First 1
if ($LASTEXITCODE -ne 0) { throw "ffprobe verification failed" }

& (Join-Path $BinDir "ffmpeg.exe") -version | Select-Object -First 1
if ($LASTEXITCODE -ne 0) { throw "ffmpeg verification failed" }

$exifVer = & (Join-Path $BinDir "exiftool.exe") -ver
if ($LASTEXITCODE -ne 0) { throw "exiftool verification failed" }
Write-Host "ExifTool $exifVer"

Write-Host "Windows scanner tools ready in $BinDir"
