#!/usr/bin/env bash
# Bundles ClamAV binaries for macOS into src-tauri/binaries/macos
# Run from project root: ./scripts/setup-clamav-macos.sh
# Requires: brew install clamav

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/src-tauri/binaries/macos"
DB_DIR="$ROOT/src-tauri/resources/clamav"
LIB_DIR="$BIN_DIR/lib"

mkdir -p "$BIN_DIR" "$DB_DIR" "$LIB_DIR"

if ! command -v clamscan >/dev/null 2>&1; then
  echo "Install ClamAV first: brew install clamav"
  exit 1
fi

CLAMSCAN="$(command -v clamscan)"
FRESHCLAM="$(command -v freshclam)"

cp "$CLAMSCAN" "$BIN_DIR/"
cp "$FRESHCLAM" "$BIN_DIR/"
chmod +x "$BIN_DIR/clamscan" "$BIN_DIR/freshclam"

copy_deps() {
  local binary="$1"
  otool -L "$binary" | tail -n +2 | awk '{print $1}' | while read -r dep; do
    case "$dep" in
      /usr/lib/*|/System/*|@executable_path/*|@loader_path/*) continue ;;
    esac
    if [ -f "$dep" ]; then
      local base
      base="$(basename "$dep")"
      cp -f "$dep" "$LIB_DIR/$base"
      install_name_tool -id "@loader_path/$base" "$LIB_DIR/$base" 2>/dev/null || true
    fi
  done
}

echo "Copying dynamic libraries..."
copy_deps "$CLAMSCAN"
copy_deps "$FRESHCLAM"

echo "Setting rpaths..."
for bin in "$BIN_DIR/clamscan" "$BIN_DIR/freshclam"; do
  install_name_tool -add_rpath "@executable_path/lib" "$bin" 2>/dev/null || true
  otool -L "$bin" | tail -n +2 | awk '{print $1}' | while read -r dep; do
    case "$dep" in
      /usr/local/*|/opt/homebrew/*)
        base="$(basename "$dep")"
        if [ -f "$LIB_DIR/$base" ]; then
          install_name_tool -change "$dep" "@loader_path/$base" "$bin" 2>/dev/null || true
        fi
        ;;
    esac
  done
done

BREW_PREFIX="$(brew --prefix clamav 2>/dev/null || brew --prefix)"
if [ -d "$BREW_PREFIX/etc/clamav/certs" ]; then
  cp -R "$BREW_PREFIX/etc/clamav/certs" "$BIN_DIR/"
fi

if [ ! -f "$DB_DIR/main.cvd" ]; then
  echo "Updating virus definitions..."
  freshclam --datadir="$DB_DIR" || true
fi

echo "Verifying bundled clamscan..."
"$BIN_DIR/clamscan" --version

echo "macOS ClamAV bundle ready in $BIN_DIR"
