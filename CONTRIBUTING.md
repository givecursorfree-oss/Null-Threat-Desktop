# Contributing to Null Threat

Thank you for helping improve Null Threat. This project is **GPL v3** open source.

## Quick start

```bash
git clone https://github.com/givecursorfree-oss/Null-Threat-Desktop.git
cd Null-Threat-Desktop
npm ci
npm run dev
```

### Requirements

| Tool | Version |
|------|---------|
| Node.js | 20+ |
| Rust | 1.82+ (stable) |
| Platform deps | See [README.md](README.md#build-from-source) |

Linux and macOS builds need WebKit/GTK or Xcode toolchain headers. CI installs these automatically; match them locally when building installers.

## Development workflow

1. Fork the repo and create a branch: `feat/short-description` or `fix/short-description`
2. Make focused changes with tests when behavior changes
3. Run checks before opening a PR:

```bash
npm run build:vite          # frontend typecheck + build
cd src-tauri && cargo test --lib 'scanner::'
cd src-tauri && cargo clippy -- -D warnings
```

4. Open a Pull Request against `main` with:
   - What changed and why
   - Screenshots for UI changes
   - Platform tested (Windows / macOS / Linux)

## Code style

- **Rust:** `cargo fmt`, no clippy warnings, `Result` over `unwrap()` in production paths
- **TypeScript/React:** match existing component patterns, Radix + Tailwind tokens in `src/`
- **Commits:** conventional prefixes (`feat:`, `fix:`, `docs:`, `chore:`)

## Scanner bundles

Release builds bundle ClamAV, YARA, ffprobe, ffmpeg, and ExifTool. Setup scripts live in `scripts/setup-*.sh` and `scripts/setup-*.ps1`. Do not commit `freshclam.conf` or local virus DB paths.

## Testing

- **Unit tests:** `cargo test --lib 'scanner::'` in `src-tauri/`
- **CI:** GitHub Actions runs frontend build, Linux scanner tests, and platform installers on every push
- **Manual matrix:** see [docs/TESTING.md](docs/TESTING.md) for the v1.0 field checklist (especially macOS and Linux)

## Pull request review

Maintainers look for:

- Security boundaries validated (paths, subprocess allowlists, IPC inputs)
- No developer machine paths in release artifacts
- Accurate user-facing copy (offline scanning vs optional online updates)
- GPL compliance when touching bundled ClamAV

## Releases

Tagged releases (`v*`) trigger automated GitHub Releases with installers and `SHA256SUMS.txt`. Maintainers with signing certificates should configure GitHub secrets per [docs/CODE_SIGNING.md](docs/CODE_SIGNING.md).

## Questions

Open a [Discussion](https://github.com/givecursorfree-oss/Null-Threat-Desktop/discussions) for design questions. Use [Issues](https://github.com/givecursorfree-oss/Null-Threat-Desktop/issues) for bugs and feature requests.
