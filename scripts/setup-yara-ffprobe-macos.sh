#!/usr/bin/env bash
# Bundles YARA, ffprobe, ffmpeg, and exiftool for macOS into src-tauri/binaries/macos
# Run from project root: ./scripts/setup-yara-ffprobe-macos.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/src-tauri/binaries/macos"
LIB_DIR="$BIN_DIR/lib"
EXIFTOOL_VERSION="13.59"
EXIFTOOL_URL="https://downloads.sourceforge.net/project/exiftool/Image-ExifTool-${EXIFTOOL_VERSION}.tar.gz"

mkdir -p "$BIN_DIR" "$LIB_DIR"

if ! command -v yara >/dev/null 2>&1 || ! command -v ffprobe >/dev/null 2>&1 || ! command -v ffmpeg >/dev/null 2>&1; then
  echo "Install tools first: brew install yara ffmpeg perl"
  exit 1
fi

YARA="$(command -v yara)"
FFPROBE="$(command -v ffprobe)"
FFMPEG="$(command -v ffmpeg)"

cp "$YARA" "$BIN_DIR/"
cp "$FFPROBE" "$BIN_DIR/"
cp "$FFMPEG" "$BIN_DIR/"
chmod +x "$BIN_DIR/yara" "$BIN_DIR/ffprobe" "$BIN_DIR/ffmpeg"

bundle_deps_for() {
  local target="$1"
  local ref_prefix="$2"
  local deps
  deps="$(otool -L "$target" | tail -n +2 | awk '{print $1}')"

  while IFS= read -r dep; do
    [ -z "$dep" ] && continue
    case "$dep" in
      /usr/lib/*|/System/Library/*) continue ;;
    esac
    local base="${dep##*/}"
    if [ -f "$dep" ] && [ ! -f "$LIB_DIR/$base" ]; then
      cp -f "$dep" "$LIB_DIR/$base"
      install_name_tool -id "@loader_path/$base" "$LIB_DIR/$base" 2>/dev/null || true
    fi
    case "$dep" in
      /opt/homebrew/*|/usr/local/*)
        if [ -f "$LIB_DIR/$base" ]; then
          install_name_tool -change "$dep" "$ref_prefix/$base" "$target" 2>/dev/null || true
        fi
        ;;
    esac
  done <<< "$deps"
}

for bin in "$BIN_DIR/yara" "$BIN_DIR/ffprobe" "$BIN_DIR/ffmpeg"; do
  install_name_tool -add_rpath "@executable_path/lib" "$bin" 2>/dev/null || true
done

for pass in $(seq 1 8); do
  before="$(find "$LIB_DIR" -maxdepth 1 -name '*.dylib' 2>/dev/null | wc -l | tr -d ' ')"
  for bin in yara ffprobe ffmpeg; do
    bundle_deps_for "$BIN_DIR/$bin" "@executable_path/lib"
  done
  for lib in "$LIB_DIR"/*.dylib; do
    [ -f "$lib" ] || continue
    bundle_deps_for "$lib" "@loader_path"
  done
  after="$(find "$LIB_DIR" -maxdepth 1 -name '*.dylib' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$before" = "$after" ] && break
done

echo "Downloading ExifTool ${EXIFTOOL_VERSION}..."
TMP="$(mktemp -d)"
curl -fsSL "$EXIFTOOL_URL" -o "$TMP/exiftool.tar.gz"
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

echo "macOS scanner tools ready in $BIN_DIR"
