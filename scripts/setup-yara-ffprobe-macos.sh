#!/usr/bin/env bash
# Bundles YARA + ffprobe for macOS into src-tauri/binaries/macos
# Run from project root: ./scripts/setup-yara-ffprobe-macos.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/src-tauri/binaries/macos"
LIB_DIR="$BIN_DIR/lib"

mkdir -p "$BIN_DIR" "$LIB_DIR"

if ! command -v yara >/dev/null 2>&1 || ! command -v ffprobe >/dev/null 2>&1; then
  echo "Install tools first: brew install yara ffmpeg"
  exit 1
fi

YARA="$(command -v yara)"
FFPROBE="$(command -v ffprobe)"

cp "$YARA" "$BIN_DIR/"
cp "$FFPROBE" "$BIN_DIR/"
chmod +x "$BIN_DIR/yara" "$BIN_DIR/ffprobe"

is_system_lib() {
  case "$1" in
    /usr/lib/*|/System/Library/*|/lib/libSystem*) return 0 ;;
    *) return 0 ;;
  esac
}

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

for bin in "$BIN_DIR/yara" "$BIN_DIR/ffprobe"; do
  install_name_tool -add_rpath "@executable_path/lib" "$bin" 2>/dev/null || true
done

for pass in $(seq 1 8); do
  before="$(find "$LIB_DIR" -maxdepth 1 -name '*.dylib' 2>/dev/null | wc -l | tr -d ' ')"
  bundle_deps_for "$BIN_DIR/yara" "@executable_path/lib"
  bundle_deps_for "$BIN_DIR/ffprobe" "@executable_path/lib"
  for lib in "$LIB_DIR"/*.dylib; do
    [ -f "$lib" ] || continue
    bundle_deps_for "$lib" "@loader_path"
  done
  after="$(find "$LIB_DIR" -maxdepth 1 -name '*.dylib' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$before" = "$after" ] && break
done

echo "Verifying bundled tools..."
"$BIN_DIR/yara" --version
"$BIN_DIR/ffprobe" -version

echo "macOS YARA + ffprobe ready in $BIN_DIR"
