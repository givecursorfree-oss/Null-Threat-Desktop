# Null Threat — Product Copy (Edit Here First)

> **Single source of truth** for hero page, README, and marketing site.  
> Update this file first, then sync to `website/index.html` and `README.md`.  
> Last updated: 2026-07-06

---

## Repo & links (replace everywhere)

| Field | Value |
|-------|-------|
| GitHub org/repo | `givecursorfree-oss/Null-Threat-Desktop` |
| GitHub URL | `https://github.com/givecursorfree-oss/Null-Threat-Desktop` |
| Actions badge | `https://img.shields.io/github/actions/workflow/status/givecursorfree-oss/Null-Threat-Desktop/build.yml?branch=main` |
| Releases URL | `https://github.com/givecursorfree-oss/Null-Threat-Desktop/releases` |
| Tagline | Scan locally. Trust nothing. |
| License | GPL v3 |
| Version badge (hero) | v0.1 Open Source |

---

## Hero section

### Badge pill
```
v0.1 Open Source · Deep Analysis · Bundled ExifTool
```

### Headline (line 1 — white)
```
Scan everything.
```

### Headline (line 2 — muted)
```
Trust nothing.
```

### Subhead (hero paragraph)
```
Four local detection engines plus multi-layer deep analysis — identity, structure, metadata, and steganography. All scanner tools bundled. No cloud uploads, no telemetry, no subscriptions. Free forever under GPL v3.
```

### Primary CTA
```
Download Free
```

### Secondary CTA
```
View on GitHub
```

### Console overlay lines (hero dashboard mock)
```
[BLOCKED] SHA-256 match — MalwareBazaar signature
[WARN] Structure: data stream detected — possible embedded payload · Risk score 42/100
[INFO] ClamAV + YARA + ExifTool initialized — all engines local
```

### Threat map node labels
| Position | Label | Color |
|----------|-------|-------|
| top-right | HASH MATCH | emerald |
| left | YARA HIT | amber |
| center | STRUCTURE | red |
| bottom-right | CLEAN | emerald |

---

## Trust bar pills

| Icon | Label |
|------|-------|
| shield-check | GPL v3 Licensed |
| database | MalwareBazaar + NSRL Hashes |
| lock | AES-256 Quarantine |
| wifi-off | 100% Offline |
| package | All Tools Bundled |

---

## How it works (3 steps)

### Step 01 — Drop a file
**Title:** Drop a file  
**Body:** Drag any file onto Null Threat or add a watched folder. No account, no upload queue.

### Step 02 — Engines analyze
**Title:** Four engines analyze  
**Body:** Hash lookup, ClamAV, YARA rules, and deep analysis (Identity · Structure · Metadata · Steg) run in parallel on your machine.

### Step 03 — Act on the verdict
**Title:** Act on the verdict  
**Body:** Review the risk score (0–100), expand Deep Analysis to see exactly what flagged, then quarantine or trust.

---

## Four engines (pipeline stepper)

### Engine 01 — SHA-256 Hash Lookup
**Description:** MalwareBazaar and NSRL hash intelligence in local SQLite. Refresh when online; works offline after first update.

### Engine 02 — ClamAV Antivirus
**Description:** Industry-standard virus signatures via bundled clamscan. Optional definition updates when online.

### Engine 03 — YARA Rule Matching
**Description:** ~23 bundled rules — polyglot files, packed executables, metadata injection, and threats hidden inside media containers.

### Engine 04 — Deep File Analysis
**Description:** Four sub-checks you can expand in scan results:
- **Identity** — magic bytes, extension mismatch, entropy (skips normal video/audio)
- **Structure** — MP4/MKV container walk, subtitle script injection scan, ffprobe video probe
- **Metadata** — ExifTool + native tag scanner for hidden scripts and payloads
- **Steganography** — chi-square and RS LSB analysis on images (video LSB not scored — avoids false positives)

---

## Features grid (6–7 cards)

Copy-paste each card:

### Card 1 — Real-time Folder Watcher
**Icon:** `lucide:folder-clock`  
**Title:** Real-time Folder Watcher  
**Body:** Monitors directories and scans files the moment they arrive.

### Card 2 — Encrypted Quarantine Vault
**Icon:** `lucide:lock`  
**Title:** Encrypted Quarantine Vault  
**Body:** AES-256-GCM isolation with restore, delete, and forensic export.

### Card 3 — SHA-256 Hash Lookup
**Icon:** `lucide:hash`  
**Title:** SHA-256 Hash Lookup  
**Body:** MalwareBazaar and NSRL signatures in local SQLite — no cloud lookup.

### Card 4 — YARA Rule Engine
**Icon:** `lucide:file-search`  
**Title:** YARA Rule Engine  
**Body:** Polyglot, packed executable, metadata abuse, and video-container threat detection.

### Card 5 — Deep File Analysis
**Icon:** `lucide:microscope`  
**Title:** Deep File Analysis  
**Body:** Identity, structure, metadata, and image steg checks — tap any result for a full breakdown.

### Card 6 — Bundled Scanner Toolchain
**Icon:** `lucide:package`  
**Title:** All Tools Bundled  
**Body:** ClamAV, YARA, ffprobe, ffmpeg, and ExifTool ship with the app — no separate installs.

### Card 7 — Privacy Controls
**Icon:** `lucide:shield-off`  
**Title:** Privacy Controls  
**Body:** Export or permanently clear scan history from Settings. Quarantine and whitelist stay intact.

### Card 8 — Offline Signature Updates
**Icon:** `lucide:wifi-off`  
**Title:** Offline Signature Updates  
**Body:** MalwareBazaar CSV download or manual import for air-gapped systems.

---

## Risk score explainer

**Section title:** Understand every verdict.  
**Section subhead:** A transparent 0–100 risk score with per-engine breakdown — not a black-box “confidence” percentage.

| Tier | Range | Description |
|------|-------|-------------|
| Clean | 0–20 | No engine flags. File appears safe. |
| Suspicious | 21–50 | Heuristic signals only — review before opening. Heuristics alone cap at 48 without a signature hit. |
| High Risk | 51–80 | Multiple engine hits — quarantine recommended. |
| Malware | 81–100 | Confirmed signature or stacked critical signals — isolate immediately. |

**UI label:** Always show `Risk score: X/100` — never “X% confidence”.

---

## Scan result mock (engines section)

**Filename:** sample_video.mp4  
**Badge:** SUSPICIOUS — Risk score 42/100  

**Engine chips:** Hash ✓ · ClamAV ✓ · YARA ✓ · Deep ⚠  

**Deep breakdown (expandable):**
- Identity: Clean — Content type MP4/MOV
- Structure: Detected — Data stream detected, possible embedded payload
- Metadata: Clean — No suspicious metadata (exiftool)
- Steganography: Clean — Video LSB not scored (by design)

---

## Bundled dependencies table

| Tool | Purpose | Bundled in release |
|------|---------|-------------------|
| ClamAV | Antivirus signature scanning | Yes |
| YARA | Rule-based file matching | Yes |
| ffprobe | Video container probe | Yes |
| ffmpeg | Video frame tooling (steg check availability) | Yes |
| ExifTool | Metadata tag extraction | Yes |

Setup script (dev): `scripts/setup-scanner-tools.ps1` (Windows) or `setup-scanner-tools.sh` (Linux/macOS)

---

## Settings — Data & Privacy

**Section title:** Data & Privacy  

**Export:** Download all scan records as CSV before clearing data.  

**Clear history:** Permanently delete every scan record from local SQLite (`nullthreat.db`). Runs VACUUM. Quarantine, whitelist, and signature databases are not affected. Cannot be undone.

---

## What NOT to claim

- ❌ “100% offline forever” — scanning is offline; optional hash/ClamAV updates need network when user refreshes
- ❌ “500,000+ hashes loaded” as a live guarantee — say MalwareBazaar + NSRL, updated when online
- ❌ “100% confidence” — use risk score X/100
- ❌ “Video steganography detection” — only image LSB; video LSB intentionally disabled
- ❌ Wrong GitHub URL `null-threat/null-threat` — use `givecursorfree-oss/Null-Threat-Desktop`

---

## Changelog (recent — for hero “what’s new”)

| Date | Feature |
|------|---------|
| 2026-07 | **v1.0** — GitHub Releases CI, SHA256SUMS, CONTRIBUTING.md, SECURITY.md, EICAR CI smoke test |
| 2026-07 | Accurate offline copy: scan offline; optional signature/hash updates when online |
| 2026-07 | Code signing pipeline (Windows Authenticode + Apple notarization when secrets configured) |
| 2026-07 | Bundled ExifTool + ffmpeg alongside ClamAV, YARA, ffprobe |
| 2026-07 | Expandable Deep Analysis breakdown in scan results |
| 2026-07 | Smart risk scoring — heuristics cap at 48/100 without signature hit |
| 2026-07 | Video false-positive fixes — entropy skip, structure parser tuning |
| 2026-07 | Risk score shown as X/100 (not confidence %) |
| 2026-07 | Clear scan history permanently in Settings |
| 2026-07 | 17 Rust unit tests for scanner pipeline |

---

## README one-paragraph intro

```
Null Threat is a free, open-source desktop security scanner built with Rust (Tauri 2) and React + TypeScript. It analyzes files using four local detection engines — SHA-256 hash lookup, ClamAV, YARA rules, and multi-stage deep analysis — entirely on your machine. Deep analysis covers file identity, container structure, metadata tags, and image steganalysis. ClamAV, YARA, ffprobe, ffmpeg, and ExifTool are bundled in release builds. Scanning runs offline with no cloud upload; optional hash and ClamAV updates use the network only when you choose to refresh. No telemetry, no subscriptions. Licensed under GPL v3.
```

---

## Open source section copy

**Title:** Built in the open.  
**Body:** Null Threat is GPL v3. Inspect the code, audit the engines, contribute YARA rules, or report false positives on GitHub Issues.  
**Links:** Contributing · Security Policy · Releases

---

*When editing the hero page: open `website/index.html` and search for section comments `SECTION 2`, `SECTION 6`, `SECTION 7`.*
