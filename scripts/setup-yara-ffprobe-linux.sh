#!/usr/bin/env bash
# Bundles YARA + ffprobe for Linux into src-tauri/binaries/linux
# Run from project root: ./scripts/setup-yara-ffprobe-linux.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/src-tauri/binaries/linux"
LIB_DIR="$BIN_DIR/lib"

mkdir -p "$BIN_DIR" "$LIB_DIR"

if ! command -v yara >/dev/null 2>&1 || ! command -v ffprobe >/dev/null 2>&1; then
  echo "Installing yara and ffmpeg via apt..."
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq yara ffmpeg patchelf
fi

YARA="$(command -v yara)"
FFPROBE="$(command -v ffprobe)"

echo "Copying YARA and ffprobe..."
cp "$YARA" "$BIN_DIR/"
cp "$FFPROBE" "$BIN_DIR/"
chmod +x "$BIN_DIR/yara" "$BIN_DIR/ffprobe"

echo "Copying shared libraries..."
for bin in "$YARA" "$FFPROBE"; do
  ldd "$bin" | awk '/=> \// { print $3 }' | sort -u | while read -r lib; do
    [ -f "$lib" ] && cp -f "$lib" "$LIB_DIR/" || true
  done
done

if command -v patchelf >/dev/null 2>&1; then
  echo "Setting rpath..."
  patchelf --set-rpath '$ORIGIN/lib' "$BIN_DIR/yara"
  patchelf --set-rpath '$ORIGIN/lib' "$BIN_DIR/ffprobe"
fi

echo "Verifying bundled tools..."
"$BIN_DIR/yara" --version
"$BIN_DIR/ffprobe" -version

echo "Linux YARA + ffprobe ready in $BIN_DIR"
