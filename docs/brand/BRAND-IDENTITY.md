# Null Threat — Brand Identity System

> Production-ready brand foundation for Null Threat, a free, open-source, offline-first desktop security scanner.

---

## Brand Personality

Five adjectives that define the Null Threat voice:

1. **Sovereign** — The product belongs to the user, not a vendor. Data never leaves the machine. The brand speaks with quiet authority about local control and self-determination.
2. **Forensic** — Precision over panic. Null Threat investigates files the way a security researcher would: methodically, with evidence, and without sensationalism.
3. **Transparent** — Open source is not a footnote; it is the product philosophy. The brand explains what it does, how it does it, and what it cannot do.
4. **Rigorous** — Four engines, entropy thresholds, YARA rules, hash databases — the brand respects technical depth and never dumbs down for marketing effect.
5. **Restrained** — No fear-mongering, no neon hacker clichés, no "your computer is infected" urgency theater. Threats are reported; calm is maintained.

---

## Brand Voice Guidelines

| Do | Don't |
|---|---|
| **Do** use precise, evidence-based language: "SHA-256 hash matched MalwareBazaar entry #482910" | **Don't** use vague alarmism: "DANGER! Your files are compromised!" |
| **Do** lead with privacy and locality: "Scans run entirely on your machine — no uploads, no telemetry" | **Don't** imply cloud superiority or suggest users need an internet connection to stay safe |
| **Do** acknowledge trade-offs honestly: "ClamAV definitions require periodic updates; air-gapped systems can import CSV manually" | **Don't** claim "100% detection" or "military-grade" without qualification |
| **Do** address developers and IT admins as peers: "Configure watched directories via Settings → Folders" | **Don't** patronize with oversimplified wizard copy that hides advanced controls |
| **Do** celebrate open source as a feature: "GPL v3 — inspect, fork, and improve the code" | **Don't** treat open source as a cost-saving gimmick or bury the license |
| **Do** use the risk score system consistently: Clean (0–20), Suspicious (21–50), High Risk (51–80), Malware (81–100) | **Don't** invent alternate severity labels (Critical, P1, Red Alert) outside the defined tiers |
| **Do** maintain a calm, dark, premium tone — silver for neutral/clean states, gold for active/threat states | **Don't** use bright red full-screen warnings, flashing animations, or stock "hacker green" terminal aesthetics |
| **Do** differentiate from cloud AV competitors by naming the architectural difference: "local engines vs. cloud submission" | **Don't** name-shame competitors directly; contrast on architecture, not brand attacks |

---

## Tagline Options

| Tagline | Rationale |
|---|---|
| **Scan locally. Trust nothing.** | Six words (with period as emphasis unit). Captures the offline-first architecture and the security researcher's default stance — verify every file, assume nothing is clean. Mirrors the hero headline pattern. |
| **Your machine. Your verdict.** | Five words. Emphasizes sovereignty and the local risk-scoring system. Positions Null Threat against cloud-dependent tools that return opaque vendor verdicts. |
| **Four engines. Zero uploads.** | Five words. Concrete, technical, immediately differentiating. Speaks to the audience that evaluates tools by architecture, not marketing. |

**Recommended primary tagline:** Scan locally. Trust nothing.

---

## Color Usage Rules

### Core Palette

| Token | Hex / Value | Role | Communicates | Never Pair With |
|---|---|---|---|---|
| **Void** | `#030304` | Page background, app canvas | Depth, focus, premium darkness | Bright saturated backgrounds (white sections, pastel cards) — breaks the dark-system identity |
| **Obsidian** | `#0a0a0a` | Elevated panels, dashboard containers, threat map backgrounds | Contained surfaces, UI depth | Pure white text blocks without sufficient contrast padding — causes eye strain |
| **Graphite** | `#18181b` | Cards, sidebar, input fields | Secondary surfaces, structure | Gold accent text on graphite without 4.5:1 contrast — fails WCAG for body copy |
| **Silver** | `linear-gradient(135deg, #a1a1aa 0%, #e4e4e7 50%, #71717a 100%)` | Primary wordmark "NULL", clean verdicts, neutral engine states, primary headings | Precision, neutrality, the "null" / clean state | Emerald or bright green — reserved for competitor association; use gold for positive active states |
| **Gold** | `linear-gradient(135deg, #92700a 0%, #d4a017 50%, #b8860b 100%)` | "THREAT" wordmark half, active scan indicators, High Risk tier, hover accents on icons | Premium alert, technical warmth, actionable attention | Pure red (#ef4444) as a primary brand color — red is reserved for Malware tier UI only, not brand decoration |
| **Steel** | `#71717a` | Body text, secondary labels, de-emphasized headline words | Supporting information, calm tone | Gold or silver gradients — muddies hierarchy |
| **Ash** | `#a1a1aa` | Muted text, placeholders, semi-transparent headline variants ("Trust nothing.") | De-emphasis without disappearing | White at full opacity on dark bg for long paragraphs — too harsh for body |
| **Snow** | `#ffffff` | Primary headings (full opacity), CTA button fill, active nav | Maximum contrast, action | Large white fields on white — only use as text or button fill, never as section background |
| **Malware Red** | `#ef4444` | Malware tier (81–100) chips, destructive actions, BLOCKED log lines | Confirmed threat, irreversible action | Gold — red and gold together imply decorative alarm, not semantic severity |
| **Clean up** | `#34d399` / emerald-400 | Clean verdict (0–20), success states, "The Null Threat Way" column accents on marketing site | Verified safe, positive confirmation | Purple — purple is reserved for "Traditional Security" problem column on marketing site only |

### Semantic Color Rules

- **Background hierarchy:** Void → Obsidian → Graphite → white/5 overlays. Never skip more than two steps in a single viewport.
- **Interactive states:** Default uses Steel text on Graphite surface. Hover adds gold/50 border or emerald/50 border depending on context (gold for brand CTAs, emerald for security-positive hovers on marketing site). Active inverts to Snow text on Graphite fill.
- **Risk tier colors:** Clean = emerald-400, Suspicious = amber-400, High Risk = orange-400, Malware = red-400. These are functional, not decorative — never use Malware Red for marketing accents.
- **Gradient usage:** Silver and Gold gradients appear only on the logo wordmark, hero headline accent words, and primary brand lockups. UI components use flat semantic colors, not gradients.

---

## Icon Style Direction

**Family:** Lucide-style geometric stroke icons (consistent with the app's `lucide-react` dependency).

| Property | Specification |
|---|---|
| **Stroke weight** | 1.5px at 24×24px base size; scale proportionally (2px at 32×32) |
| **Corner radius** | Rounded stroke caps and joins (`stroke-linecap="round"`, `stroke-linejoin="round"`) — no sharp miter joins |
| **Corner radius (containers)** | Icon containers use `rounded-md` (6px) or `rounded-lg` (8px) — never fully circular except for status dots |
| **Metaphor family** | Security primitives: shield, lock, eye, scan/search, file, folder, hash (#), database, quarantine/box, radar, activity/pulse. Avoid skulls, crossbones, generic "virus" blobs, or padlock-with-globe cloud icons |
| **Size scale** | 16px (inline/chips), 20px (nav/buttons), 24px (feature cards), 32px (empty states) |
| **Color** | Default: `#71717a` (Steel). Hover: `#34d399` (emerald-400) on marketing site, `#d4a017` (gold) in app UI. Active/semantic: tier colors only |
| **Filled vs. stroke** | Stroke-only by default. Filled variants reserved for active nav items and tier badges |
| **Animation** | Icons do not animate independently. Container hover transitions only (`transition-colors 150ms`) |

---

## Typography Rules

**Primary typeface:** Inter (Google Fonts) — weights 300, 400, 500, 600  
**Fallback stack:** `'Inter', ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`

### Heading Scale (Marketing + App Shell)

| Level | Size | Weight | Line Height | Letter Spacing | Usage |
|---|---|---|---|---|---|
| Display | `clamp(3rem, 7vw, 4.5rem)` / 72px | 600 (Semibold) | 1.05 | `-0.02em` | Hero headlines |
| H1 | 48px / `text-5xl` | 600 | 1.1 | `-0.02em` | Page titles |
| H2 | 36px / `text-4xl` | 600 | 1.15 | `-0.01em` | Section headers |
| H3 | 24px / `text-2xl` | 600 | 1.25 | `0` | Card titles, feature names |
| H4 | 20px / `text-xl` | 500 | 1.3 | `0` | Subsection labels |
| H5 | 16px / `text-base` | 600 | 1.4 | `0.02em` | Overline labels (uppercase optional) |

### Body Scale

| Level | Size | Weight | Line Height | Usage |
|---|---|---|---|---|
| Body LG | 18px | 400 | 1.6 | Marketing subheads, onboarding |
| Body | 16px | 400 | 1.5 | Primary app body copy |
| Body SM | 14px | 400 | 1.55 | Secondary descriptions, card body |
| Caption | 12px | 500 | 1.5 | Timestamps, metadata, table headers |
| Micro | 10px | 500 | 1.4 | Badges, engine labels, log prefixes |

### Weight Usage

- **300 (Light):** Never used for UI text. Reserved for large decorative display sublines if needed.
- **400 (Regular):** All body copy, descriptions, table cell content.
- **500 (Medium):** Buttons, nav links, labels, badge text, form field labels.
- **600 (Semibold):** All headings, stat numbers, verdict titles, active nav items.

### UI Label Letter-Spacing

- **Navigation links:** `tracking-normal` (0)
- **Uppercase section labels:** `tracking-widest` (0.1em) at 10–12px
- **Button text:** `tracking-normal`
- **Risk tier chips:** `tracking-wide` (0.05em) at 11px uppercase
- **Engine name labels:** `tracking-normal` at 12px monospace optional for hash/log output only (`font-mono`)

### Mixed-Weight Headline Pattern

Hero and key marketing headlines use inline weight/contrast splits:
- **Primary clause:** `text-white font-semibold` — e.g., "Scan everything."
- **Secondary clause:** `text-neutral-500 font-semibold` — e.g., "Trust nothing."

This pattern is a brand signature. Do not use color alone to split clauses.

---

## Logo Concept Description

### Overview

The Null Threat logo is a **split-shield symbol** paired with a **split-color wordmark**, communicating duality: the clean/null state (silver) and the threat analysis state (gold). The construction is geometric, angular, and premium — designed for dark backgrounds.

### Symbol — The Split Shield

**Canvas:** 512×512px artboard. Shield occupies 80% height, centered.

**Outer shield shape:**
- Classic heater-shield silhouette: flat top edge (20% width centered), angled upper shoulders at 35° from horizontal, straight tapered sides converging to a pointed base at bottom center.
- Overall aspect ratio: 1:1.15 (width:height).
- Outer stroke: none. Shape is fill-only.

**Vertical bisection at exact center (x = 256px):**
The shield is divided into two halves that share the center seam but have distinct visual treatments.

**Left half — "NULL" (Silver):**
- Fill: brushed metallic silver linear gradient, top-left to bottom-right: `#71717a` → `#d4d4d8` → `#a1a1aa`.
- Interior negative space forms a stylized letter **N** using the shield's left edge as the N's left stem:
  - Left vertical bar: the shield's left border edge, full height of the shield interior.
  - Diagonal stroke: from top-right of the left bar (at 25% shield height) down to bottom-left junction (at 75% height), width 28px, same silver fill.
  - Right vertical bar of the N: parallel to left bar, inset 40px from center seam, height spanning 20%–80% of shield interior.
- All N strokes use **sharp 45° chamfered corners** — no rounded ends. This reads as engineered, not friendly.

**Right half — "THREAT" (Gold Circuit):**
- Fill: transparent / void (`#000000` matching background) — the right half is defined by its border and interior elements, not a solid fill.
- Border: 3px stroke following the shield's right outer edge and the center seam, color gold gradient `#92700a` → `#d4a017`.
- Interior circuit traces (3–4 vertical lines):
  - Line 1: x = 58% of shield width, height 40% of interior, anchored at bottom third.
  - Line 2: x = 65%, height 60%.
  - Line 3: x = 72%, height 35%.
  - Line 4 (optional): x = 78%, height 50%.
  - Each line: 2px stroke, gold `#d4a017`, terminates in a 6px circle (node) at the top endpoint.
  - Lines are strictly vertical — no diagonal routing.
- The circuit motif represents data analysis, engine processing, and digital forensics.

**3D bevel treatment (both halves):**
- Subtle top-left highlight overlay at 15% opacity white on the silver half.
- Subtle bottom-right shadow overlay at 20% opacity black on both halves.
- Creates embossed badge appearance without skeuomorphic excess.

### Wordmark — "NULL THREAT"

**Position:** Centered below the shield symbol. Gap between symbol base and wordmark cap height: 16px at standard lockup size.

**Typeface:** Custom geometric sans (Inter SemiBold as production substitute). All caps.

**"NULL":**
- Fill: same silver gradient as shield left half.
- Letter-spacing: `0.12em` (tracked wide for premium feel).

**Space:** Single word space (not en-dash, not stacked).

**"THREAT":**
- Fill: same gold gradient as shield right half border.
- Letter-spacing: `0.12em`.
- **Stylized A:** The crossbar of the A is removed. The letter is rendered as an upward-pointing chevron (∧) — two diagonal strokes meeting at 60° apex, no horizontal bar. This matches the angular N geometry in the symbol.

**Wordmark size ratio:** At standard horizontal lockup, wordmark cap height = 22% of shield height.

### Lockup Variants

1. **Horizontal (primary):** Symbol above wordmark, center-aligned. Minimum clear space: 1× shield width on all sides.
2. **Symbol only:** For app icon (512×512), favicon (32×32 simplified — remove circuit detail below 64px, keep N + gold border arc).
3. **Wordmark only:** For nav bars where symbol is separate. Nav uses simplified `w-5 h-5` gradient square (silver left half, gold right half) as icon substitute per website implementation quirk.

### Minimum Sizes

- Full lockup: 120px wide minimum.
- Symbol only: 32px minimum (favicon).
- Wordmark only: 80px wide minimum.

### Background Requirements

- Logo is designed for **dark backgrounds** (#030304 to #0a0a0a).
- Do not place on white or light gray without creating a dark container pill first.
- Do not rotate, skew, stretch, recolor individual halves independently, or add drop shadows beyond the built-in bevel.

---

*Document version 1.0 — Null Threat Brand Identity System*
