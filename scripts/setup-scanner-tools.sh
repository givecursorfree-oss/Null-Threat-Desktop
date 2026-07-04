#!/usr/bin/env bash
# One-command setup: ClamAV + YARA + ffprobe (Linux/macOS)
# Usage: ./scripts/setup-scanner-tools.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== Null Threat: bundling scanner tools ==="

if [[ "$OSTYPE" == "darwin"* ]]; then
  command -v brew >/dev/null 2>&1 || { echo "Install Homebrew first"; exit 1; }
  brew list clamav >/dev/null 2>&1 || brew install clamav
  brew list yara >/dev/null 2>&1 || brew install yara
  brew list ffmpeg >/dev/null 2>&1 || brew install ffmpeg
  chmod +x scripts/setup-clamav-macos.sh scripts/setup-yara-ffprobe-macos.sh
  ./scripts/setup-clamav-macos.sh
  ./scripts/setup-yara-ffprobe-macos.sh
else
  chmod +x scripts/setup-clamav-linux.sh scripts/setup-yara-ffprobe-linux.sh
  ./scripts/setup-clamav-linux.sh
  ./scripts/setup-yara-ffprobe-linux.sh
fi

echo ""
echo "All scanner tools bundled. Run: npm run build"
