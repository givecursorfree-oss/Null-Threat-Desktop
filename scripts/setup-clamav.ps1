# Populates bundled ClamAV binaries and virus definitions for Null Threat.
# Run from the null-threat project root:
#   .\scripts\setup-clamav.ps1
#   .\scripts\setup-clamav.ps1 -ZipPath "C:\Users\you\Downloads\clamav-1.5.2.win.x64.zip"
#   .\scripts\setup-clamav.ps1 -ClamAvPath "C:\ClamAV"

param(
    [string]$ZipPath,
    [string]$ClamAvPath,
    [switch]$SkipFreshclam,
    [switch]$AllowArchMismatch
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BinDir = Join-Path $ProjectRoot "src-tauri/binaries/windows"
$DbDir = Join-Path $ProjectRoot "src-tauri/resources/clamav"
$TauriConf = Join-Path $ProjectRoot "src-tauri/tauri.conf.json"

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path $DbDir | Out-Null

function Get-SystemArch {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { return "arm64" }
    if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { return "x64" }
    if ($env:PROCESSOR_ARCHITECTURE -eq "x86") { return "win32" }
    return "x64"
}

function Get-ZipArch {
    param([string]$Path)
    $name = [System.IO.Path]::GetFileName($Path).ToLowerInvariant()
    if ($name -match "\.win\.arm64\.") { return "arm64" }
    if ($name -match "\.win\.x64\.") { return "x64" }
    if ($name -match "\.win\.win32\.") { return "win32" }
    return $null
}

function Find-ClamAvInstall {
    if ($ClamAvPath -and (Test-Path $ClamAvPath)) {
        $clamscan = Join-Path $ClamAvPath "clamscan.exe"
        if (Test-Path $clamscan) { return (Resolve-Path $ClamAvPath).Path }
    }

    $candidates = @(
        "${env:ProgramFiles}\ClamAV",
        "${env:ProgramFiles(x86)}\ClamAV",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\ClamAV.ClamAV_*"
    )

    foreach ($pattern in $candidates) {
        $matches = Get-Item -Path $pattern -ErrorAction SilentlyContinue
        foreach ($dir in $matches) {
            $clamscan = Join-Path $dir.FullName "clamscan.exe"
            if (Test-Path $clamscan) { return $dir.FullName }
        }
    }

    return $null
}

function Expand-ClamAvZip {
    param([string]$Path)

    $extractRoot = Join-Path $env:TEMP "null-threat-clamav-setup"
    if (Test-Path $extractRoot) { Remove-Item -Recurse -Force $extractRoot }
    New-Item -ItemType Directory -Force -Path $extractRoot | Out-Null

    Write-Host "Extracting $Path ..."
    Expand-Archive -Path $Path -DestinationPath $extractRoot -Force

    $inner = Get-ChildItem -Path $extractRoot -Directory | Where-Object {
        Test-Path (Join-Path $_.FullName "clamscan.exe")
    } | Select-Object -First 1

    if (-not $inner) {
        throw "Could not find clamscan.exe inside ZIP archive."
    }

    return $inner.FullName
}

function Copy-ClamAvRuntime {
    param([string]$SourceRoot)

    Write-Host "Copying ClamAV runtime from: $SourceRoot"

    $runtimeFiles = @(
        "clamscan.exe",
        "freshclam.exe",
        "libclamav.dll",
        "libfreshclam.dll",
        "libclammspack.dll",
        "libclamunrar.dll",
        "libclamunrar_iface.dll",
        "libcurl.dll",
        "libxml2.dll",
        "libbz2.dll",
        "json-c.dll",
        "pcre2-8.dll",
        "nghttp2.dll",
        "libssh2.dll",
        "pthreadVC3.dll",
        "pdcurses.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "msvcp140.dll",
        "msvcp140_1.dll",
        "msvcp140_2.dll",
        "msvcp140_atomic_wait.dll",
        "msvcp140_codecvt_ids.dll",
        "concrt140.dll"
    )

    # OpenSSL DLL names differ by architecture
    foreach ($dll in @("libcrypto-3-x64.dll", "libssl-3-x64.dll", "libcrypto-3-arm64.dll", "libssl-3-arm64.dll")) {
        if (Test-Path (Join-Path $SourceRoot $dll)) { $runtimeFiles += $dll }
    }

    foreach ($file in $runtimeFiles) {
        $src = Join-Path $SourceRoot $file
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination (Join-Path $BinDir $file) -Force
            Write-Host "  copied $file"
        }
    }

    $certsSrc = Join-Path $SourceRoot "certs"
    if (Test-Path $certsSrc) {
        Copy-Item -Path $certsSrc -Destination (Join-Path $BinDir "certs") -Recurse -Force
        Write-Host "  copied certs/"
    }

    if (-not (Test-Path (Join-Path $BinDir "clamscan.exe"))) {
        throw "clamscan.exe was not copied."
    }

    # Virus DB must live in resources/clamav, not next to binaries
    Get-ChildItem -Path $BinDir -Include *.cvd,*.cld,*.cvdb -File -ErrorAction SilentlyContinue | Remove-Item -Force
}

function Copy-VirusDatabase {
    param([string]$SourceRoot)

    $patterns = @("*.cvd", "*.cld", "*.cvdb")
    $copied = $false

    foreach ($pattern in $patterns) {
        Get-ChildItem -Path $SourceRoot -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            $dest = Join-Path $DbDir $_.Name
            if ($_.FullName -eq $dest) { $copied = $true; return }
            Copy-Item -Path $_.FullName -Destination $dest -Force
            Write-Host "  copied database $($_.Name)"
            $copied = $true
        }
    }

    return $copied
}

function Invoke-Freshclam {
    param([string]$RuntimeRoot)

    $freshclam = Join-Path $RuntimeRoot "freshclam.exe"
    if (-not (Test-Path $freshclam)) {
        Write-Host "freshclam.exe not found; skipping database download." -ForegroundColor Yellow
        return $false
    }

    $confSample = Join-Path $RuntimeRoot "conf_examples/freshclam.conf.sample"
    $conf = Join-Path $env:TEMP "nullthreat-freshclam-setup.conf"
    if ((Test-Path $confSample) -and -not (Test-Path $conf)) {
        Copy-Item $confSample $conf
        (Get-Content $conf) `
            -replace '^Example', '# Example' `
            -replace '^#DatabaseDirectory .*', "DatabaseDirectory $DbDir" `
            | Set-Content $conf
    } elseif (-not (Test-Path $conf)) {
        @"
DatabaseDirectory $DbDir
DNSDatabaseInfo current.cvd.clamav.net
DatabaseMirror database.clamav.net
"@ | Set-Content $conf
    }

    Write-Host "Downloading virus definitions with freshclam (may take a few minutes)..."
    Push-Location $RuntimeRoot
    try {
        & $freshclam --config-file=$conf 2>&1 | ForEach-Object { Write-Host $_ }
        return (Test-VirusDatabase)
    } finally {
        Pop-Location
    }
}

function Test-VirusDatabase {
    $patterns = @("*.cvd", "*.cld", "*.cvdb")
    foreach ($pattern in $patterns) {
        if (Get-ChildItem -Path $DbDir -Filter $pattern -ErrorAction SilentlyContinue | Select-Object -First 1) {
            return $true
        }
    }
    return $false
}

function Update-TauriBundleResources {
    $confText = Get-Content -Raw -Path $TauriConf
    $resourceEntry = '"binaries/windows/*"'

    if ($confText -notmatch [regex]::Escape('"binaries/windows/*"')) {
        if ($confText -match '"resources/clamav/\*"') {
            $confText = $confText -replace '("resources/clamav/\*")', "`$1,`n      `"binaries/windows/*`""
        } else {
            $confText = $confText -replace '(\s+"\.\./rules/\*")', "`$1,`n      `"binaries/windows/*`",`n      `"resources/clamav/*`""
        }
        Set-Content -Path $TauriConf -Value $confText -NoNewline
        Write-Host "Updated tauri.conf.json bundle resources."
    }
}

# Resolve ClamAV source
$clamRoot = $null
$sysArch = Get-SystemArch

if ($ZipPath) {
    if (-not (Test-Path $ZipPath)) { throw "ZIP not found: $ZipPath" }

    $zipArch = Get-ZipArch -Path $ZipPath
    if ($zipArch -and $zipArch -ne $sysArch -and -not $AllowArchMismatch) {
        Write-Host ""
        Write-Host "Architecture mismatch!" -ForegroundColor Red
        Write-Host "  Your PC:     $sysArch ($env:PROCESSOR_ARCHITECTURE)"
        Write-Host "  ZIP package: $zipArch"
        Write-Host ""
        Write-Host "This ZIP will NOT run on your machine. Download the matching build:" -ForegroundColor Yellow
        Write-Host "  https://www.clamav.net/downloads/production/clamav-1.5.2.win.$sysArch.zip" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Re-run with -AllowArchMismatch only if you are bundling for another platform." -ForegroundColor Yellow
        exit 1
    }

    $clamRoot = Expand-ClamAvZip -Path $ZipPath
} else {
    $clamRoot = Find-ClamAvInstall
}

if (-not $clamRoot) {
    Write-Host "ClamAV not found." -ForegroundColor Yellow
    Write-Host "Install via winget, extract a Windows ZIP, or pass -ZipPath:" -ForegroundColor Yellow
    Write-Host "  winget install ClamAV.ClamAV" -ForegroundColor Cyan
    Write-Host "  .\scripts\setup-clamav.ps1 -ZipPath `"C:\path\clamav-1.5.2.win.x64.zip`"" -ForegroundColor Cyan
    exit 1
}

Copy-ClamAvRuntime -SourceRoot $clamRoot

$dbCopied = Copy-VirusDatabase -SourceRoot $clamRoot
if (-not $dbCopied -and -not $SkipFreshclam) {
    $dbCopied = Invoke-Freshclam -RuntimeRoot $BinDir
}

if (-not $dbCopied) {
    Write-Host ""
    Write-Host "No virus database files yet." -ForegroundColor Yellow
    Write-Host "Run freshclam manually or copy *.cvd/*.cld into:" -ForegroundColor Yellow
    Write-Host "  $DbDir"
    exit 1
}

# Verify clamscan runs
Write-Host ""
Write-Host "Verifying clamscan..."
Push-Location $BinDir
try {
    $version = & (Join-Path $BinDir "clamscan.exe") --version 2>&1
    Write-Host $version
} catch {
    Write-Host "clamscan verification failed: $_" -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}

Update-TauriBundleResources

$staleRuntimeConf = Join-Path $BinDir "freshclam.conf"
if (Test-Path $staleRuntimeConf) {
    Remove-Item $staleRuntimeConf -Force
    Write-Host "Removed stale freshclam.conf from bundle directory (runtime config is generated by the app)."
}

Write-Host ""
Write-Host "Bundled ClamAV setup complete." -ForegroundColor Green
Write-Host "  Binaries: $BinDir"
Write-Host "  Database: $DbDir"
Write-Host "Rebuild Null Threat: npm run build"
