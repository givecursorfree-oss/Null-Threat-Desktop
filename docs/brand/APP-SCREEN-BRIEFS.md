# Null Threat — App Screen Design Briefs

> Detailed design briefs for six core desktop application screens. All screens use the dark theme defined in `docs/design/tokens.css`.

---

## Global App Shell

### Layout Structure
- **Window chrome:** Tauri native titlebar (platform-dependent). No custom traffic lights on macOS unless `titleBarStyle: overlay` is enabled.
- **Sidebar:** Fixed left, 240px wide, `bg-[#0a0a0a] border-r border-[#27272a]`. Contains nav items with lucide icons.
- **Main content:** Flex-1, scrollable, `bg-[#050505]`. PageHeader at top, content below with `p-6` padding.
- **Background layer:** Optional UnicornStudio or glass-wave background at z-0, content at z-10 with semi-transparent scrim.

### Sidebar Nav Items
| Icon | Label | Route |
|---|---|---|
| layout-dashboard | Dashboard | `/` |
| scan-search | Scan File | `/scan` |
| archive | Quarantine | `/quarantine` |
| history | History | `/history` |
| settings | Settings | `/settings` |

Active state: `bg-[#27272a] text-white`. Inactive: `text-[#71717a] hover:text-[#a1a1aa]`.

---

## Screen 1 — Dashboard

### Purpose
At-a-glance protection status, aggregate statistics, recent scan activity feed, and live engine status indicators.

### Layout Structure
```
┌─────────────────────────────────────────────────────────┐
│ PageHeader: "Dashboard"                    [Scan File CTA]│
├─────────────────────────────────────────────────────────┤
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐    │
│ │ Protection   │ │ Files Scanned│ │ Threats Found│    │
│ │ Status Card  │ │ Stat Card    │ │ Stat Card    │    │
│ └──────────────┘ └──────────────┘ └──────────────┘    │
│ ┌────────────────────────────┐ ┌─────────────────────┐  │
│ │ Recent Scan Feed (2/3)     │ │ Engine Status (1/3) │  │
│ │                            │ │                     │  │
│ └────────────────────────────┘ └─────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

Grid: `grid-cols-1 lg:grid-cols-3 gap-6`. Stat cards span full width in row 1 (3 equal columns). Row 2: feed `lg:col-span-2`, engine panel `lg:col-span-1`.

### UI Components

**Protection Status Card**
- Large shield icon (32px) with color reflecting state: emerald (protected), amber (partial — ClamAV offline), red (watcher disabled)
- Title: "Protected" / "Partial Protection" / "Unprotected" — `--text-heading-sm`, semibold, white
- Subtitle: engine count online — `--text-body-sm`, `--color-text-secondary`
- Background: `--color-surface-default`, `--radius-lg`, `--shadow-elevation-2`, padding `--spacing-6`

**Stat Cards (×3)**
- Label: `--text-caption`, uppercase, `--color-text-muted`, `tracking-wider`
- Value: `--text-display`, semibold, white
- Delta indicator (optional): small arrow + percentage, emerald or red
- Same card styling as protection card

**Recent Scan Feed**
- Card header: "Recent Scans" + "View All" link to History
- List items (max 8 visible, scroll if more):
  - File icon + truncated filename (monospace, `--text-body-sm`)
  - VerdictBadge chip (tier color)
  - Relative timestamp (`2m ago`) — `--text-caption`, muted
  - Hover: `bg-[#27272a]/50` row highlight
- Empty state: scan-search icon (48px, muted) + "No scans yet" + "Scan a file" button

**Engine Status Panel**
- Card header: "Engines"
- Four rows, one per engine:
  - Engine name (Hash, ClamAV, YARA, Deep Analysis)
  - Status dot: green (ready), amber (degraded), gray (skipped)
  - Signature count or version string (right-aligned, caption)
- Live progress bar appears when any engine is actively scanning (see Screen 2)

### Visual States
| State | Protection Card | Feed |
|---|---|---|
| Default | Green shield, "Protected" | Latest scans listed |
| Scanning | Pulsing gold border on card | New item appears at top with "Scanning…" badge |
| ClamAV offline | Amber shield, "Partial Protection" | Normal — ClamAV shows "Skipped" in results |
| Empty (first launch) | Green shield | Empty state with onboarding hint |

### Color Usage
- Background: `#050505`
- Cards: `#18181b` with `#27272a` borders
- Positive indicators: `--color-clean`
- Active scan pulse: `--color-accent-gold` at 50% border opacity

### Typography
- Page title: `--text-heading` (24px semibold)
- Stat values: `--text-display` (32px semibold)
- Feed items: `--text-body-sm` (13px regular)

### Micro-Interactions
- Stat values count up from 0 on first dashboard load (400ms, `--easing-default`)
- New scan feed item slides in from top (`translateY(-8px)` → `0`, opacity 0 → 1, 250ms)
- Engine status dots pulse gently when engine is active (opacity 1 → 0.5 → 1, 1.5s loop)
- "Scan File" CTA in header: primary white button, `--duration-fast` hover

---

## Screen 2 — Active Scan View

### Purpose
Show real-time progress while all four engines analyze a dropped or selected file.

### Layout Structure
```
┌─────────────────────────────────────────────────────────┐
│ PageHeader: "Scanning…"                                 │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ File Info Bar: icon + filename + size + path        │ │
│ └─────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Engine 1: SHA-256 Hash Lookup    [████████░░] 80%   │ │
│ │ Engine 2: ClamAV Scan            [██████░░░░] 60%   │ │
│ │ Engine 3: YARA Rule Match        [████░░░░░░] 40%   │ │
│ │ Engine 4: Deep File Analysis     [██░░░░░░░░] 20%   │ │
│ └─────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Live Results Stream (appears as engines complete)   │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

Single column, max-width 720px centered or full-width with padding.

### UI Components

**File Info Bar**
- File type icon (inferred from extension)
- Filename: `--text-heading-sm`, semibold, white, truncate with tooltip
- Metadata row: file size, MIME type, SHA-256 prefix — `--text-caption`, monospace, muted
- Background: `--color-surface-default`, border `--color-border-subtle`

**Engine Progress Rows (×4)**
- Component: `EngineProgressBar`
- Left: engine icon (color-coded per engine token) + engine name
- Center: progress bar — track `#27272a`, fill engine color, height 6px, `--radius-sm`
- Right: percentage or status text ("Matching…", "Clean", "Match found")
- Completed state: check-circle icon (emerald) or alert-triangle (amber/red) replaces spinner
- Active state: indeterminate shimmer on progress bar fill

**Live Results Stream**
- Appears below progress section as engines complete
- Each result row:
  - Engine badge (colored chip)
  - Finding text (e.g., "YARA rule `packed_upx` matched")
  - Severity inline badge
- Results accumulate — do not replace previous rows
- Auto-scroll to latest result

**Cancel Button**
- Secondary button, bottom-right: "Cancel Scan"
- Destructive hover not needed — neutral secondary styling

### Visual States
| State | Progress Bars | Results Stream |
|---|---|---|
| Initializing | All at 0%, spinners | Hidden |
| Running | Independent progress per engine | Rows appear as each completes |
| Complete | All 100%, checkmarks | Full result set visible + "View Full Report" CTA |
| Cancelled | Frozen at current % | Partial results preserved |
| Error (single engine) | Failed engine shows red X | Error message inline: "ClamAV not found — skipped" |

### Color Usage
- Engine colors from tokens: hash=sky, clamav=emerald, yara=purple, deep=gold
- Progress bar fill uses engine color at full opacity
- Match found: result row gets left border 3px in severity color

### Typography
- Engine names: `--text-body`, medium weight
- Result findings: `--text-body-sm`, regular, `--color-text-secondary`
- Hash output: `--font-mono`, `--text-caption`

### Micro-Interactions
- Progress bars animate width with `--duration-normal` (250ms) — transform scaleX, not width property
- Result rows slide in from left (`translateX(-12px)` → `0`, 200ms, stagger 80ms)
- On all engines complete: brief gold flash on container border (opacity 0 → 1 → 0, 600ms) then navigate prompt
- Spinner: CSS rotate animation on lucide loader icon, 1s linear infinite

---

## Screen 3 — Scan Result Detail

### Purpose
Full verdict presentation with per-engine breakdown, risk score gauge, and action buttons (quarantine, ignore, export).

### Layout Structure
```
┌─────────────────────────────────────────────────────────┐
│ ← Back to History                                       │
├─────────────────────────────────────────────────────────┤
│ ┌──────────────────────┐ ┌────────────────────────────┐ │
│ │ Verdict Card         │ │ Risk Score Gauge           │ │
│ │ (tier color border)  │ │ (arc 0-100)                │ │
│ └──────────────────────┘ └────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Per-Engine Chips (4 across)                         │ │
│ └─────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Detailed Findings List                              │ │
│ └─────────────────────────────────────────────────────┘ │
│ [Quarantine] [Export Report] [Scan Another] [Dismiss]   │
└─────────────────────────────────────────────────────────┘
```

Two-column top row on desktop (`grid-cols-1 md:grid-cols-2`). Full-width sections below.

### UI Components

**Verdict Card**
- Left border 4px in tier color (clean/suspicious/high-risk/malware)
- Verdict label: "CLEAN" / "SUSPICIOUS" / "HIGH RISK" / "MALWARE" — uppercase, `--text-heading`, tier color
- Filename + file path (truncated)
- Scan timestamp
- File hash (full SHA-256, monospace, copy button)

**Risk Score Gauge**
- Component: `ConfidenceMeter`
- Semicircular arc gauge, 0–100 scale
- Needle or filled arc in tier color
- Center: large score number (`67`) + `/100` subscript
- Tier label below gauge

**Per-Engine Chips (×4)**
- Horizontal flex row, wrap on mobile
- Each chip: engine icon + name + status icon (✓, ⚠, ✗, —)
- Chip background: engine color at 10% opacity
- Chip border: engine color at 30% opacity
- Click/hover expands tooltip with engine-specific findings

**Detailed Findings List**
- Expandable accordion sections per engine
- Each finding: rule name / hash ID / entropy value + description
- YARA matches show rule file and matched strings (truncated)
- ClamAV shows signature name
- Hash lookup shows MalwareBazaar or NSRL reference ID

**Action Buttons**
- **Quarantine:** Primary destructive — red outline, only enabled for Suspicious+ tiers
- **Export Report:** Secondary — exports CSV/JSON forensic report
- **Scan Another:** Primary white button
- **Dismiss:** Ghost text link

### Visual States
| Verdict Tier | Card Border | Gauge Color | Quarantine Button |
|---|---|---|---|
| Clean (0–20) | Emerald | Emerald | Disabled, hidden |
| Suspicious (21–50) | Amber | Amber | Enabled, amber outline |
| High Risk (51–80) | Orange | Orange | Enabled, orange fill |
| Malware (81–100) | Red | Red | Enabled, red fill, prominent |

### Color Usage
- Tier colors drive all accent decisions on this screen
- Clean verdict: subdued palette, no alarm colors
- Malware verdict: red card border pulse (once, 800ms)

### Typography
- Verdict label: `--text-heading` (24px), uppercase, tier color
- Score number: `--text-display` (32px), white
- Finding descriptions: `--text-body-sm`
- Hash: `--font-mono`, `--text-caption`

### Micro-Interactions
- Gauge needle animates from 0 to final score on mount (800ms, `--easing-spring`)
- Engine chips stagger fade-in (100ms delay each)
- Copy hash button: icon switches to checkmark for 2s on click
- Quarantine click: confirmation modal with file details before proceeding

---

## Screen 4 — Quarantine Vault

### Purpose
Manage AES-256-GCM encrypted quarantined files — view, restore, permanently delete, or generate forensic reports.

### Layout Structure
```
┌─────────────────────────────────────────────────────────┐
│ PageHeader: "Quarantine Vault"     [🔒 AES-256-GCM]    │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Encrypted file table                                │ │
│ │ ┌──────┬──────────┬──────────┬─────────┬──────────┐ │ │
│ │ │ Name │ Original │ Quarant. │ Risk    │ Actions  │ │ │
│ │ │      │ Path     │ Date     │ Score   │          │ │ │
│ │ └──────┴──────────┴──────────┴─────────┴──────────┘ │ │
│ └─────────────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Forensic Report Panel (selected file detail)         │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

Full-width table with detail panel below or as slide-over drawer on selection.

### UI Components

**Vault Header Badge**
- Lock icon + "AES-256-GCM Encrypted" — `--text-caption`, gold color, pill badge
- Item count: "12 files isolated"

**Quarantine Table**
- Columns: Quarantine ID (mono), Original Filename, Original Path (truncated), Quarantine Date, Risk Score chip, Actions
- Row hover: `bg-[#27272a]/30`
- Selected row: `bg-[#27272a]` with gold left border 3px
- Empty state: lock icon + "Vault is empty" + "Quarantined files appear here"
- Sort: by date (default desc), by risk score

**Action Buttons (per row)**
- **Restore:** Secondary button — returns file to original path (with overwrite confirmation)
- **Delete:** Destructive ghost — permanent removal from vault
- **Report:** Icon button — generates forensic report

**Forensic Report Panel**
- Appears when row selected or "Report" clicked
- Sections: File Metadata, Scan Results at Time of Quarantine, Engine Findings, Hash Values
- Export buttons: CSV, JSON, PDF (PDF optional/future)
- Report header: "Forensic Report — QT-2026-00482"

**Bulk Actions Bar**
- Appears when checkbox selection active
- "Restore Selected" / "Delete Selected" with count

### Visual States
| State | Table | Detail Panel |
|---|---|---|
| Empty | Empty state illustration | Hidden |
| Populated | Files listed | Hidden until selection |
| Selected | Row highlighted | Report panel slides up (300ms) |
| Restoring | Row shows spinner | Progress overlay |
| Delete confirm | Modal overlay | Modal with file details + "This cannot be undone" |

### Color Usage
- Vault badge: gold accent (encryption = premium security)
- Risk chips: tier semantic colors
- Delete actions: `--color-destructive`
- Restore actions: `--color-success` outline

### Typography
- Table headers: `--text-caption`, uppercase, muted, `tracking-wider`
- File names: `--text-body-sm`, white
- Paths: `--font-mono`, `--text-caption`, muted
- Report section headers: `--text-heading-sm`

### Micro-Interactions
- Row selection: gold left border slides in (`scaleY 0 → 1`, 200ms)
- Delete confirmation modal: `--easing-spring` entrance
- Restore success: toast notification bottom-right, emerald, auto-dismiss 4s
- Report panel: slide up from bottom (`translateY(100%)` → `0`, 300ms)

---

## Screen 5 — Scan History

### Purpose
Searchable, filterable log of all past scans with risk chips and CSV export.

### Layout Structure
```
┌─────────────────────────────────────────────────────────┐
│ PageHeader: "Scan History"              [Export CSV ↓]  │
├─────────────────────────────────────────────────────────┤
│ [Search input] [Verdict filter ▾] [Date range ▾] [Clear]│
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────┐ │
│ │ History Table                                       │ │
│ └─────────────────────────────────────────────────────┘ │
│ ← 1 2 3 … 12 →                          Showing 1-50   │
└─────────────────────────────────────────────────────────┘
```

### UI Components

**Filter Bar**
- Search input: filters by filename, hash prefix — `--color-surface-raised` background, search icon left
- Verdict filter dropdown: All, Clean, Suspicious, High Risk, Malware — multi-select optional
- Date range: preset options (Today, 7 days, 30 days, All time)
- Clear filters: ghost button, appears when any filter active

**History Table**
- Columns: Date/Time, Filename, Path (truncated), Risk Score (numeric + chip), Engines Triggered (icon row), Actions (view detail)
- Default sort: date descending
- Row click navigates to Scan Result Detail (Screen 3)
- Pagination: 50 rows per page

**Export CSV Button**
- Header right placement
- Primary secondary styling
- Downloads full filtered result set (not just current page)
- Columns in export: timestamp, filename, path, sha256, risk_score, verdict, engine_results_json

**Risk Chips in Table**
- Compact variant of VerdictBadge
- Pill shape, tier color background at 15%    tier color text
- Score number inline: "High Risk · 67"

### Visual States
| State | Table | Filters |
|---|---|---|
| Loading | Skeleton rows (5) | Disabled |
| Populated | Data rows | Active |
| Filtered empty | "No scans match filters" | Active with clear CTA |
| Exporting | Normal | Export button shows spinner |

### Color Usage
- Table header: `#0a0a0a` background
- Alternating rows: subtle `#18181b` / transparent (optional, prefer hover-only)
- Filter active indicator: gold dot on filter button

### Typography
- Table data: `--text-body-sm`
- Timestamps: `--font-mono`, `--text-caption`
- Export button: `--text-body`, medium

### Micro-Interactions
- Search debounced 300ms before filter applies
- Filter dropdown: fade + slide down (150ms)
- Row hover: background transition 150ms
- Export: button text changes to "Exporting…" during generation

---

## Screen 6 — Settings

### Purpose
Configure watched folders, signature update schedule, file whitelist, and advanced engine options.

### Layout Structure
```
┌─────────────────────────────────────────────────────────┐
│ PageHeader: "Settings"                                  │
├─────────────────────────────────────────────────────────┤
│ ┌─ Watched Folders ────────────────────────────────────┐│
│ │ [folder list with add/remove]                        ││
│ └──────────────────────────────────────────────────────┘│
│ ┌─ Signature Updates ──────────────────────────────────┐│
│ │ [auto/manual toggle] [last updated] [update now]     ││
│ └──────────────────────────────────────────────────────┘│
│ ┌─ Whitelist ──────────────────────────────────────────┐│
│ │ [path/hash whitelist entries]                        ││
│ └──────────────────────────────────────────────────────┘│
│ ┌─ Advanced ───────────────────────────────────────────┐│
│ │ [advanced mode toggle] [engine toggles] [entropy]    ││
│ └──────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

Single column, max-width 640px. Settings grouped in bordered cards with section headers.

### UI Components

**Watched Folders Section**
- Section header: "Watched Folders" + description "Automatically scan new files in these directories"
- Folder list: each row shows path (monospace), enable/disable toggle, remove button (×)
- "Add Folder" button: opens native folder picker via Tauri dialog
- First-add triggers FolderWatchConsentModal (onboarding)
- Max folders indicator if limit exists

**Signature Updates Section**
- Auto-update toggle (Switch component): "Download MalwareBazaar CSV automatically"
- Update schedule dropdown (when auto enabled): Daily, Weekly, Manual only
- Last updated timestamp: "Signatures last updated: Jun 28, 2026 — 482,910 entries"
- "Update Now" button: triggers manual update, shows progress
- "Import CSV" button: for air-gapped systems — file picker for local CSV
- SignatureUpdateBanner appears at app top when signatures are stale (>7 days)

**Whitelist Section**
- Tab or toggle: "File Paths" / "SHA-256 Hashes"
- Path whitelist: list of glob patterns or exact paths
- Hash whitelist: list of SHA-256 hashes with optional label
- Add entry: inline input + "Add" button
- Whitelisted items skip all engines (shown with info badge in scan results)

**Advanced Section**
- Master toggle: "Advanced Mode" — reveals engine-level controls when enabled
- Per-engine enable/disable toggles (Hash, ClamAV, YARA, Deep Analysis)
- Entropy threshold slider: default 7.2, range 5.0–8.0, step 0.1
- ClamAV path override (text input)
- ffprobe path override (text input)
- "Reset to Defaults" ghost button

### Visual States
| Control | Off | On |
|---|---|---|
| Folder watcher toggle | Gray switch | Gold switch |
| Auto-update toggle | Gray | Emerald |
| Advanced mode | Sections collapsed/hidden | All advanced controls visible |
| Engine toggle (individual) | "Skipped" label in scans | Normal operation |

### Color Usage
- Section cards: `--color-surface-default`, `--radius-lg`
- Section headers: white, `--text-heading-sm`
- Descriptions: `--color-text-secondary`
- Destructive remove buttons: red on hover only
- Toggle on state: gold for watcher, emerald for updates

### Typography
- Section headers: `--text-heading-sm`, semibold
- Descriptions: `--text-body-sm`, secondary color
- Path inputs: `--font-mono`, `--text-body-sm`
- Toggle labels: `--text-body`, medium

### Micro-Interactions
- Toggle switches: thumb slides with `--duration-fast` (150ms)
- Add folder: native dialog opens instantly, list updates on return with slide-in row
- "Update Now": button → progress bar → success toast with entry count
- Advanced mode toggle: sections expand with height animation (250ms, `--easing-default`)
- Remove folder: row fades out and collapses (200ms) — no confirmation for remove, undo toast instead

---

*Document version 1.0 — Null Threat App Screen Design Briefs*
