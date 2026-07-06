# Code signing and notarization

Null Threat release installers are built to support **Windows Authenticode** and **Apple notarization** when signing secrets are configured in CI or on a release machine.

Unsigned builds still work for local development and open-source contributors.

## Windows (Authenticode)

### What gets signed

- `null-threat.exe` (application binary)
- MSI and NSIS installers produced under `src-tauri/target/release/bundle/`

### GitHub Actions secrets

| Secret | Description |
|--------|-------------|
| `WINDOWS_CERTIFICATE` | Base64-encoded `.pfx` / `.p12` code signing certificate |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password for the PFX file |

When both secrets are set, the `build-windows` workflow imports the certificate and Tauri signs the bundle automatically.

### Local signing (PowerShell)

```powershell
$env:WINDOWS_CERTIFICATE = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\to\codesign.pfx"))
$env:WINDOWS_CERTIFICATE_PASSWORD = "your-pfx-password"
npm run build
```

### Timestamp server

Configured in `src-tauri/tauri.conf.json`:

- Algorithm: `sha256`
- Timestamp URL: `http://timestamp.digicert.com`

## macOS (sign + notarize)

### What gets signed

- `Null Threat.app`
- DMG installer

### GitHub Actions secrets

| Secret | Description |
|--------|-------------|
| `APPLE_CERTIFICATE` | Base64-encoded `.p12` Developer ID Application certificate |
| `APPLE_CERTIFICATE_PASSWORD` | P12 password |
| `APPLE_SIGNING_IDENTITY` | e.g. `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_ID` | Apple ID email used for notarization |
| `APPLE_PASSWORD` | App-specific password (not your Apple ID password) |
| `APPLE_TEAM_ID` | 10-character Team ID |

When these secrets are present, Tauri signs with **hardened runtime** and submits the build for **notarization**.

### Entitlements

`src-tauri/Entitlements.plist` includes the standard Tauri/WebView entitlements required for hardened runtime.

### Local signing

```bash
export APPLE_CERTIFICATE="$(base64 -i DeveloperID.p12)"
export APPLE_CERTIFICATE_PASSWORD="..."
export APPLE_SIGNING_IDENTITY="Developer ID Application: ..."
export APPLE_ID="you@example.com"
export APPLE_PASSWORD="app-specific-password"
export APPLE_TEAM_ID="XXXXXXXXXX"
npm run build
```

## Linux

Linux `.deb` and AppImage artifacts are not code-signed in this pipeline. Distribute checksums (SHA-256) with releases.

## Verifying a signed build

**Windows**

```powershell
Get-AuthenticodeSignature ".\Null Threat.exe"
```

**macOS**

```bash
spctl -a -vv -t install "/Applications/Null Threat.app"
codesign -dv --verbose=4 "/Applications/Null Threat.app"
```

## Security notes

- Never commit PFX/P12 files or passwords to the repository.
- Rotate app-specific passwords if a CI secret is exposed.
- Code signing proves publisher identity; it does not replace malware scanning of the project source.
