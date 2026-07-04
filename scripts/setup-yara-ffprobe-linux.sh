#!/usr/bin/env bash
# Bundles YARA, ffprobe, ffmpeg, and exiftool for Linux into src-tauri/binaries/linux
# Run from project root: ./scripts/setup-yara-ffprobe-linux.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/src-tauri/binaries/linux"
LIB_DIR="$BIN_DIR/lib"
EXIFTOOL_VERSION="13.59"
EXIFTOOL_URL="https://downloads.sourceforge.net/project/exiftool/Image-ExifTool-${EXIFTOOL_VERSION}.tar.gz"

mkdir -p "$BIN_DIR" "$LIB_DIR"

if ! command -v yara >/dev/null 2>&1 || ! command -v ffprobe >/dev/null 2>&1 || ! command -v ffmpeg >/dev/null 2>&1; then
  echo "Installing yara and ffmpeg via apt..."
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq yara ffmpeg patchelf perl curl
fi

YARA="$(command -v yara)"
FFPROBE="$(command -v ffprobe)"
FFMPEG="$(command -v ffmpeg)"

echo "Copying YARA, ffprobe, and ffmpeg..."
cp "$YARA" "$BIN_DIR/"
cp "$FFPROBE" "$BIN_DIR/"
cp "$FFMPEG" "$BIN_DIR/"
chmod +x "$BIN_DIR/yara" "$BIN_DIR/ffprobe" "$BIN_DIR/ffmpeg"

echo "Copying shared libraries..."
for bin in "$YARA" "$FFPROBE" "$FFMPEG"; do
  ldd "$bin" | awk '/=> \// { print $3 }' | sort -u | while read -r lib; do
    [ -f "$lib" ] && cp -f "$lib" "$LIB_DIR/" || true
  done
done

if command -v patchelf >/dev/null 2>&1; then
  echo "Setting rpath..."
  for bin in yara ffprobe ffmpeg; do
    patchelf --set-rpath '$ORIGIN/lib' "$BIN_DIR/$bin"
  done
fi

echo "Downloading ExifTool ${EXIFTOOL_VERSION}..."
TMP="$(mktemp -d)"
curl -fsSL -L "$EXIFTOOL_URL" -o "$TMP/exiftool.tar.gz"
tar -xzf "$TMP/exiftool.tar.gz" -C "$TMP"
EXIF_DIR="$(find "$TMP" -maxdepth 1 -type d -name 'Image-ExifTool-*' | head -1)"
if [ -z "$EXIF_DIR" ]; then
  echo "ExifTool extract failed"
  exit 1
fi

cp "$EXIF_DIR/exiftool" "$BIN_DIR/exiftool"
chmod +x "$BIN_DIR/exiftool"
rm -rf "$BIN_DIR/exiftool_lib"
cp -a "$EXIF_DIR/lib" "$BIN_DIR/exiftool_lib"
rm -rf "$TMP"

echo "Verifying bundled tools..."
"$BIN_DIR/yara" --version
"$BIN_DIR/ffprobe" -version
"$BIN_DIR/ffmpeg" -version
PERL5LIB="$BIN_DIR/exiftool_lib" "$BIN_DIR/exiftool" -ver

echo "Linux scanner tools ready in $BIN_DIR"
