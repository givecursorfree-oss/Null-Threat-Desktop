# Null Threat v1.0 — Field Test Checklist

Use this checklist before tagging a release or after major scanner changes. CI covers builds and EICAR detection; these steps validate real user flows on each OS.

## All platforms

- [ ] Fresh install from release artifact (not `npm run dev`)
- [ ] First launch: bundled ClamAV DB copies to app data, no crash
- [ ] Scan a clean file → verdict Clean, score 0–20
- [ ] Scan EICAR test file → Malware detected (ClamAV or hash)
- [ ] Settings → Update hashes (online) → count increases
- [ ] Settings → Update ClamAV signatures (online) → last updated changes
- [ ] Airplane mode: scan still works with cached signatures
- [ ] Quarantine a file → restore → file intact
- [ ] Export scan history CSV and single-scan JSON/PDF
- [ ] Clear scan history → history empty, quarantine unchanged

## Windows

- [ ] MSI install (per-machine or per-user)
- [ ] NSIS `.exe` install
- [ ] SmartScreen: if unsigned, "More info → Run anyway" after verifying SHA256 from release
- [ ] Data under `%APPDATA%\dev.nullthreat.desktop\`
- [ ] Quarantine key in Credential Manager (if available)

## macOS

- [ ] DMG drag-to-Applications install
- [ ] Gatekeeper: if unsigned, right-click → Open once after verifying SHA256
- [ ] Notarized build: no Gatekeeper block (requires Apple CI secrets)
- [ ] Data under `~/Library/Application Support/dev.nullthreat.desktop/`
- [ ] ffprobe/ffmpeg deep analysis on sample MP4

## Linux

- [ ] `.deb` install on Ubuntu 24.04
- [ ] AppImage runs on clean VM without system ClamAV
- [ ] Data under `~/.local/share/dev.nullthreat.desktop/` (or XDG equivalent)
- [ ] Secret Service keychain fallback when available

## Reporting results

File issues with: OS version, installer type, steps, expected vs actual. Tag `platform:windows`, `platform:macos`, or `platform:linux`.

Contributors: see [CONTRIBUTING.md](../CONTRIBUTING.md).
