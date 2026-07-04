# Null Threat — Agent Instructions

## gstack (recommended)

This project uses [gstack](https://github.com/garrytan/gstack) for AI-assisted planning, review, QA, shipping, and security workflows in Cursor.

**Runtime root:** `.cursor/skills/gstack/` (global install at `~/.cursor/skills/gstack`)

Use **gstack** skills for web browsing (`gstack-browse`), never raw browser MCP unless gstack is unavailable.

### Common skills

| Skill | Use when |
|-------|----------|
| `gstack-office-hours` | Shaping a new feature or product idea |
| `gstack-plan-ceo-review` | Strategic scope review before building |
| `gstack-review` | Code review on a branch |
| `gstack-qa` | Browser QA on a URL or staging build |
| `gstack-ship` | Prepare and land a PR |
| `gstack-cso` | Security audit (OWASP / STRIDE) |
| `gstack-investigate` | Root-cause debugging |

### Install / update (Windows)

```powershell
git clone --single-branch --depth 1 https://github.com/garrytan/gstack.git "$env:USERPROFILE\.cursor\skills\gstack"
cd "$env:USERPROFILE\.cursor\skills\gstack"
bun install
bun run gen:skill-docs --host cursor
.\scripts\setup-gstack.ps1
```

Or run `.\scripts\setup-gstack.ps1` from the Null Threat repo root after cloning gstack globally.

### Null Threat context

- Desktop app: Tauri 2 + React + Rust (`shieldscan/`)
- CI: `.github/workflows/build.yml` (Linux, macOS, Windows)
- Scanner engines: hash intel, ClamAV, YARA, deep analysis (entropy, magic bytes, video)
