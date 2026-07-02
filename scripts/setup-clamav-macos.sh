#!/usr/bin/env bash
# Bundles ClamAV binaries for macOS into src-tauri/binaries/macos
# Run from project root: ./scripts/setup-clamav-macos.sh
# Requires: brew install clamav

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/src-tauri/binaries/macos"
DB_DIR="$ROOT/src-tauri/resources/clamav"
LIB_DIR="$BIN_DIR/lib"
FRESHCLAM_CONF="$DB_DIR/freshclam.conf"

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

for bin in "$BIN_DIR/clamscan" "$BIN_DIR/freshclam"; do
  install_name_tool -add_rpath "@executable_path/lib" "$bin" 2>/dev/null || true
done

is_system_lib() {
  case "$1" in
    /usr/lib/*|/System/Library/*|/lib/libSystem*|/lib/libresolv*) return 0 ;;
    *) return 1 ;;
  esac
}

bundle_deps_for() {
  local target="$1"
  local ref_prefix="$2"

  local deps
  deps="$(otool -L "$target" | tail -n +2 | awk '{print $1}')"

  while IFS= read -r dep; do
    [ -z "$dep" ] && continue
    is_system_lib "$dep" && continue

    local base="${dep##*/}"
    local src=""

    if [ -f "$dep" ]; then
      src="$dep"
    elif [ -f "$LIB_DIR/$base" ]; then
      src=""
    else
      continue
    fi

    if [ -n "$src" ] && [ ! -f "$LIB_DIR/$base" ]; then
      cp -f "$src" "$LIB_DIR/$base"
      install_name_tool -id "@loader_path/$base" "$LIB_DIR/$base" 2>/dev/null || true
    fi

    case "$dep" in
      /opt/homebrew/*|/usr/local/*)
        install_name_tool -change "$dep" "$ref_prefix/$base" "$target" 2>/dev/null || true
        ;;
      @loader_path/*)
        if [ "$ref_prefix" = "@executable_path/lib" ] && [ -f "$LIB_DIR/$base" ]; then
          install_name_tool -change "$dep" "@executable_path/lib/$base" "$target" 2>/dev/null || true
        fi
        ;;
    esac
  done <<< "$deps"
}

echo "Copying dynamic libraries..."
for pass in $(seq 1 10); do
  before="$(find "$LIB_DIR" -maxdepth 1 -name '*.dylib' 2>/dev/null | wc -l | tr -d ' ')"
  bundle_deps_for "$BIN_DIR/clamscan" "@executable_path/lib"
  bundle_deps_for "$BIN_DIR/freshclam" "@executable_path/lib"
  for lib in "$LIB_DIR"/*.dylib; do
    [ -f "$lib" ] || continue
    bundle_deps_for "$lib" "@loader_path"
  done
  after="$(find "$LIB_DIR" -maxdepth 1 -name '*.dylib' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$before" = "$after" ] && break
done

BREW_PREFIX="$(brew --prefix clamav 2>/dev/null || brew --prefix)"
if [ -d "$BREW_PREFIX/etc/clamav/certs" ]; then
  cp -R "$BREW_PREFIX/etc/clamav/certs" "$BIN_DIR/"
fi

if [ ! -f "$DB_DIR/main.cvd" ]; then
  echo "Updating virus definitions..."
  cat > "$FRESHCLAM_CONF" <<EOF
DatabaseDirectory $DB_DIR
DatabaseMirror database.clamav.net
DNSDatabaseInfo current.cvd.clamav.net
EOF
  "$FRESHCLAM" --config-file="$FRESHCLAM_CONF" --datadir="$DB_DIR" 2>/dev/null || true
fi

echo "Verifying bundled clamscan..."
"$BIN_DIR/clamscan" --version

echo "macOS ClamAV bundle ready in $BIN_DIR"
