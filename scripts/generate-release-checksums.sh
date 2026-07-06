#!/usr/bin/env bash
# Generate SHA256SUMS.txt for all release artifacts under dist/
set -euo pipefail

ROOT="${1:-dist}"
OUT="${2:-SHA256SUMS.txt}"

cd "$ROOT"
find . -type f \( \
  -name '*.msi' -o -name '*.exe' -o -name '*.dmg' -o \
  -name '*.deb' -o -name '*.AppImage' -o -name '*.app' \
  \) ! -path '*/\.*' -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "../$OUT"

echo "Wrote $(wc -l < "../$OUT") checksums to $OUT"
cat "../$OUT"
