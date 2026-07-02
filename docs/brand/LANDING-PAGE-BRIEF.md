# Null Threat — Landing Page Design Brief

> Section-by-section design brief for the Null Threat marketing website. Implementation reference: `website/index.html` (SENTRY-layout fidelity, Null Threat brand).

---

## Global Layout Constants

| Property | Value |
|---|---|
| Page background | `#030304` (Void) |
| Content container | `max-w-7xl mx-auto px-6` |
| Section vertical padding | `py-24` (96px) default; hero `pt-32 pb-20` |
| Font | Inter 300/400/500/600 via Google Fonts |
| Body text | `text-neutral-400` |
| Selection | `selection:bg-indigo-500/30 selection:text-indigo-200` |
| Grid overlay utility | `.grid-bg` — 50×50px lines at `rgba(255,255,255,0.03)` |
| Radial glow utility | `.radial-glow` — sky-400 at 8% opacity, 60% falloff |

---

## Section 1 — Navigation Bar

### Layout Description
Fixed top bar, full viewport width, height 64px (`h-16`). Three-zone flex layout: logo left, nav links center (hidden below `md`), CTA buttons right. Background: `bg-[#030304]/80 backdrop-blur-md`. Bottom border: `border-b border-white/5`.

### Visual Hierarchy
1. Logo lockup (highest contrast — white/silver)
2. Primary CTA "Download" (white fill, black text)
3. Nav links (muted gray)
4. Secondary "GitHub" link (text link)

### Key UI Components
- **Logo:** `w-5 h-5` square div with split silver/gold gradient (`bg-gradient-to-br from-neutral-400 via-neutral-200 to-amber-600`) + "NULL THREAT" in `font-semibold tracking-tight text-white`
- **Nav links:** Platform, Engines, Docs, GitHub — `text-xs font-medium text-neutral-400 hover:text-white transition-colors`
- **Sign in equivalent:** "GitHub" text link — `text-xs font-medium text-neutral-400`
- **Primary CTA:** "Download" — `bg-white text-black text-xs font-medium px-4 py-2 rounded-sm hover:bg-neutral-200 transition-colors`

### Copy Direction
- Logo: NULL THREAT
- Links reflect product structure, not enterprise SaaS categories
- CTA: "Download" not "Get Started" — open-source desktop app, no signup

### Spacing Notes
- Container: `max-w-7xl mx-auto px-6 h-16 flex items-center justify-between`
- Nav link gap: `gap-8`
- Button group gap: `gap-4`

### Animation / Interaction
- Nav background opacity increases on scroll (optional JS: add `bg-[#030304]/95` after 50px scroll)
- Link hover: color transition 150ms
- CTA hover: background lightens to neutral-200
- No mega-menu — flat link structure

---

## Section 2 — Hero & Threat Map

### Layout Description
Full-width section below nav. Two-part vertical stack:
1. **Text block** — centered, max-width constrained headline + subhead + CTAs
2. **Abstract Dashboard Visual** — full container width, aspect ratio ~16/9, min-height 480px

Background layers (z-index stack):
- z-10: Aura Background Component (UnicornStudio particles + linear-gradient mask)
- z-20: Grid overlay (`.grid-bg`)
- z-30: Content (headline, dashboard visual)

### Visual Hierarchy
1. H1 headline — "Scan everything." (white bold) + "Trust nothing." (neutral-500 bold)
2. Version badge — pinging dot + "v1.0 Open Source"
3. Abstract dashboard visual (threat map)
4. Subhead paragraph
5. CTA button row

### Key UI Components
- **Version badge:** `inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/5 text-xs text-neutral-300` with `animate-ping` dot in emerald-400
- **H1:** `text-5xl md:text-7xl font-semibold tracking-tight leading-[1.1]`
- **Subhead:** `text-lg text-neutral-400 max-w-2xl mx-auto mt-6`
- **CTA row:** Primary white button + secondary ghost button with border
- **Abstract Dashboard Visual:**
  - Container: `border border-white/10 bg-[#0a0a0a] rounded-lg overflow-hidden relative`
  - **Radar effect:** `absolute inset-0 flex items-center justify-center` → inner div `w-[150%] h-[150%] animate-spin-slow` with conic-gradient radar sweep, masked by radial-gradient
  - **SVG attack paths:** ViewBox 0 0 1000 400, three paths — one animated solid stroke (emerald), two dashed passive connections (white/20)
  - **Threat Map Nodes (4):** Absolute positioned ping dots at:
    - Node 1: `top-[28%] left-[72%]` — emerald, labeled "HASH MATCH"
    - Node 2: `top-[55%] left-[25%]` — amber, labeled "YARA HIT"
    - Node 3: `top-[38%] left-[48%]` — red, labeled "ENTROPY HIGH"
    - Node 4: `top-[68%] left-[62%]` — emerald, labeled "CLEAN"
  - **Console UI Overlay (bottom):** `absolute bottom-0 left-0 right-0 bg-black/60 backdrop-blur-sm border-t border-white/5 p-4 font-mono text-xs`
    - Line 1 (100% opacity): `[BLOCKED] SHA-256 match — MalwareBazaar #MB-482910`
    - Line 2 (60% opacity): `[WARN] Shannon entropy 7.8/8.0 — packed executable suspected`
    - Line 3 (40% opacity): `[INFO] ClamAV engine initialized — 500,000+ signatures loaded`

### Copy Direction
- Headline: Action verb + skeptical second clause
- Subhead: One sentence on four local engines, no cloud, GPL v3
- Badge: Current release version + "Open Source" not "Now Available"

### Spacing Notes
- Hero text: `text-center mb-16`
- Dashboard visual: `mt-8` below CTAs or `mt-16` if CTAs below headline
- Internal dashboard padding: `p-6 min-h-[420px]`

### Animation / Interaction
- UnicornStudio particles initialize on load via `UnicornStudio.init()` project ID `EET25BiXxR2StNXZvAzF`
- Radar: `@keyframes spin { to { transform: rotate(360deg) } }` — 8s linear infinite
- Attack path: `stroke-dashoffset` animation 200 → -200 over 2s infinite
- Ping nodes: Tailwind `animate-ping` on inner dot, outer ring static
- Console lines: fade-in stagger on scroll into view (optional GSAP, 100ms delay each)

---

## Section 3 — Social Proof / Trust Bar

### Layout Description
Horizontal strip, full container width. Single row of trust indicators — not client logos (open-source project), but **architecture trust signals**.

### Visual Hierarchy
1. Section label (micro, uppercase, tracked)
2. Trust metric pills in horizontal flex row

### Key UI Components
- **Trust pills:** `flex items-center gap-2 px-4 py-2 rounded border border-white/10 bg-white/[0.02] text-sm text-neutral-400`
  - Icons: lucide shield-check, github, lock, wifi-off
  - Labels: "GPL v3 Licensed", "500K+ Signatures", "AES-256 Quarantine", "100% Offline"

### Copy Direction
Factual, verifiable claims. No "Trusted by 10,000 companies."

### Spacing Notes
- Section: `py-12 border-y border-white/5`
- Pill gap: `gap-4 flex-wrap justify-center`

### Animation / Interaction
- Subtle hover: `hover:border-white/20 transition-colors`
- Optional: horizontal auto-scroll marquee on mobile

---

## Section 4 — How It Works (3 Steps)

### Layout Description
Three-column grid (`grid-cols-1 md:grid-cols-3 gap-8`). Centered section header above grid.

### Visual Hierarchy
1. Section H2
2. Section subhead
3. Step cards (equal weight)

### Key UI Components
- **Step card:** Icon box + step number + title + description
- **Icon container:** `w-10 h-10 rounded border border-white/10 flex items-center justify-center`
  - Icons: `download` (step 1), `scan-search` (step 2), `shield-check` (step 3)
- **Step number:** `text-xs text-neutral-500 font-mono` — "01", "02", "03"
- **Title:** `text-lg font-semibold text-white mt-4`
- **Description:** `text-sm text-neutral-400 mt-2`

### Copy Direction
- **01 — Drop a file:** "Drag any file onto Null Threat or add a watched folder. No account, no upload queue."
- **02 — Four engines analyze:** "Hash lookup, ClamAV, YARA rules, and deep structural analysis run in parallel on your machine."
- **03 — Act on the verdict:** "Review the 0–100 risk score, quarantine threats to an encrypted vault, or export forensic reports."

### Spacing Notes
- Section: `py-24`
- Header margin bottom: `mb-16`
- Card internal: icon → 16px → number → 16px → title → 8px → description

### Animation / Interaction
- Icon box hover: `hover:border-emerald-500/50 transition-colors`
- Cards fade-up on scroll with 100ms stagger per column

---

## Section 5 — Features Grid

### Layout Description
3×2 grid (`grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6`). Section header left-aligned or centered.

### Visual Hierarchy
1. Section H2 + subhead
2. Feature cards (uniform)

### Key UI Components
- **Feature card:** `p-6 rounded border border-white/10 bg-white/[0.02] hover:bg-white/[0.04] transition-all group`
- **Icon:** `text-neutral-400 group-hover:text-emerald-400 transition-colors` — 20px lucide icon
- **Title:** `text-base font-semibold text-white mt-4`
- **Description:** `text-sm text-neutral-400 mt-2 leading-relaxed`

### Feature List (6 cards)
1. **Real-time Folder Watcher** — `folder-clock` — Monitors directories and scans files the moment they arrive.
2. **Encrypted Quarantine Vault** — `lock` — AES-256-GCM isolation with restore, delete, and forensic export.
3. **SHA-256 Hash Lookup** — `hash` — 500,000+ MalwareBazaar and NSRL signatures in local SQLite.
4. **YARA Rule Engine** — `file-search` — Polyglot, packed executable, and metadata injection detection.
5. **Deep File Analysis** — `microscope` — Magic bytes, Shannon entropy, ffprobe container inspection.
6. **Offline Signature Updates** — `wifi-off` — MalwareBazaar CSV download or manual import for air-gapped systems.

### Spacing Notes
- Section: `py-24`
- Grid gap: 24px
- Card padding: 24px

### Animation / Interaction
- Card hover: background lightens, icon color shifts to emerald-400
- `transition-all duration-200`

---

## Section 6 — Scan Pipeline Deep-Dive

### Layout Description
Two-column split on desktop (`grid-cols-1 lg:grid-cols-2 gap-16 items-center`). Left: vertical engine stepper. Right: live scan result card mockup.

### Visual Hierarchy
1. Section label + H2
2. Engine stepper (sequential narrative)
3. Result card (visual payoff)

### Key UI Components
- **Vertical stepper:**
  - Step row: number pill + connector line + engine name + description
  - Connector: `w-px h-6 bg-white/10 ml-5`
  - Number pill: `w-10 h-10 rounded border border-white/10 flex items-center justify-center text-xs font-mono text-neutral-400`
  - Active/completed step: border-emerald-500/50, text-emerald-400
- **Result card mockup:**
  - Container: `border border-white/10 bg-[#0a0a0a] rounded-lg p-6`
  - Header: filename `invoice_Q4.exe` + risk badge "HIGH RISK — 67/100"
  - **Mini bar graph:** 4 bars representing engine scores
    - Bars 1–3: `bg-white/20 h-8`
    - Bar 4 (YARA): `bg-purple-500 h-10 shadow-[0_0_15px_rgba(168,85,247,0.5)]` — tallest, glowing
  - Engine chips below: Hash ✓, ClamAV ✓, YARA ⚠, Deep Analysis ✓

### Copy Direction
- H2: "Four engines. One local verdict."
- Step descriptions name the engine and one concrete detection example each

### Spacing Notes
- Section: `py-24`
- Stepper step gap: 0 (connector lines bridge steps)
- Result card: min-width 360px

### Animation / Interaction
- Stepper steps highlight sequentially on scroll (Intersection Observer, 600ms per step)
- Purple bar pulses glow on loop

---

## Section 7 — Risk Score Explainer

### Layout Description
Centered content, max-width 3xl. Horizontal tier bar showing four color-coded segments.

### Visual Hierarchy
1. H2: "Understand every verdict."
2. Tier bar (visual anchor)
3. Four tier description cards below

### Key UI Components
- **Tier bar:** Full-width flex row, 4 equal segments, height 8px, rounded-full overflow-hidden
  - Clean: `bg-emerald-500` (0–20)
  - Suspicious: `bg-amber-400` (21–50)
  - High Risk: `bg-orange-500` (51–80)
  - Malware: `bg-red-500` (81–100)
- **Tier cards:** 4-column grid, each with color dot, range label, description
- **Score gauge mockup:** Semicircle arc or horizontal slider showing needle at 67

### Copy Direction
- Clean (0–20): "No engine flags. File appears safe."
- Suspicious (21–50): "Minor anomalies — review before executing."
- High Risk (51–80): "Multiple engine hits — quarantine recommended."
- Malware (81–100): "Confirmed threat — isolate immediately."

### Spacing Notes
- Section: `py-24`
- Tier bar margin: `mb-12`
- Tier cards gap: `gap-6`

### Animation / Interaction
- Gauge needle animates from 0 to 67 on scroll into view
- Tier segments illuminate sequentially left-to-right

---

## Section 8 — Open Source / Community Section

### Layout Description
Two-column split. Left: copy + GitHub CTA. Right: repo stats card or contribution checklist.

### Visual Hierarchy
1. H2
2. GPL v3 explanation
3. GitHub star/fork CTAs
4. Contribution paths

### Key UI Components
- **GitHub CTA button:** `border border-white/10 bg-white/[0.02] hover:bg-white/[0.04] px-6 py-3 rounded flex items-center gap-2`
- **Stat blocks:** Stars, forks, contributors (placeholder counts)
- **Contribution cards:** YARA rules, engine integrations, UI improvements

### Copy Direction
- "Null Threat is GPL v3. Inspect the code, audit the engines, submit a pull request."
- Link to CONTRIBUTING.md and SECURITY.md
- No "Join our Discord" unless Discord exists — use GitHub Issues instead

### Spacing Notes
- Section: `py-24`
- Column gap: 64px

### Animation / Interaction
- GitHub button icon rotates on hover (subtle, 15deg)

---

## Section 9 — Download CTA Section

### Layout Description
Full-bleed background image with overlay. Centered content stack.

### Visual Hierarchy
1. Background image (Unsplash cyber/security)
2. Emerald radial glow overlay
3. H2 headline
4. Platform download buttons
5. Secondary link to build-from-source docs

### Key UI Components
- **Background:** `https://images.unsplash.com/photo-1707430393809-784967fe6fee?w=3840&q=80` with `bg-cover bg-center`
- **Overlay:** `bg-[#030304]/80` + `.radial-glow` emerald variant
- **H2:** "Security that never phones home." — `text-4xl md:text-5xl font-semibold text-white`
- **Platform buttons:** Windows, macOS, Linux — white outline buttons with lucide icons
- **Subtext:** "Free forever. No account required."

### Spacing Notes
- Section: `py-32`
- Content: `max-w-3xl mx-auto text-center`
        -6`
- Button row gap: 16px, flex-wrap

### Animation / Interaction
- Background parallax at 0.3× scroll speed (transform only)
- Buttons: hover fill white, text black transition

---

## Section 10 — Footer

### Layout Description
6-column grid on desktop (`grid-cols-2 md:grid-cols-6`), 2-column on mobile. Bottom bar with copyright and social icons.

### Visual Hierarchy
1. Logo + tagline (column 1–2)
2. Link groups (columns 3–6)
3. Bottom bar (full width, separated by border)

### Key UI Components
- **Logo:** Same `w-5 h-5` square + "NULL THREAT"
- **Link groups:**
  - Product: Features, Engines, Download, Changelog
  - Security: Quarantine, Risk Score, YARA Rules, Security Policy
  - Resources: Documentation, Build from Source, Signature Updates, FAQ
  - Community: GitHub, Issues, Contributing, License
- **Bottom bar:** `border-t border-white/5 pt-8 mt-12 flex justify-between`
  - Copyright: `© 2026 Null Threat. GPL v3.`
  - Social icons: GitHub, Twitter/X, LinkedIn — lucide icons, `text-neutral-500 hover:text-white`

### Spacing Notes
- Footer: `py-16`
- Column header: `text-xs font-semibold text-white uppercase tracking-wider mb-4`
- Link: `text-sm text-neutral-400 hover:text-white block mb-2`

### Animation / Interaction
- Link hover color transition 150ms
- No accordion on mobile — 2-column grid preserves all links

---

*Document version 1.0 — Null Threat Landing Page Design Brief*
