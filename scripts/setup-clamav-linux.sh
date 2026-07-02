#!/usr/bin/env bash
# Bundles ClamAV binaries for Linux into src-tauri/binaries/linux
# Run from project root: ./scripts/setup-clamav-linux.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/src-tauri/binaries/linux"
DB_DIR="$ROOT/src-tauri/resources/clamav"
LIB_DIR="$BIN_DIR/lib"

mkdir -p "$BIN_DIR" "$DB_DIR" "$LIB_DIR"

if ! command -v clamscan >/dev/null 2>&1; then
  echo "Installing clamav via apt..."
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clamav clamav-freshclam patchelf
fi

CLAMSCAN="$(command -v clamscan)"
FRESHCLAM="$(command -v freshclam)"

echo "Copying ClamAV binaries..."
cp "$CLAMSCAN" "$BIN_DIR/"
cp "$FRESHCLAM" "$BIN_DIR/"
chmod +x "$BIN_DIR/clamscan" "$BIN_DIR/freshclam"

echo "Copying shared libraries..."
ldd "$CLAMSCAN" | awk '/=> \// { print $3 }' | sort -u | while read -r lib; do
  [ -f "$lib" ] && cp -f "$lib" "$LIB_DIR/" || true
done

if command -v patchelf >/dev/null 2>&1; then
  echo "Setting rpath for bundled binaries..."
  patchelf --set-rpath '$ORIGIN/lib' "$BIN_DIR/clamscan"
  patchelf --set-rpath '$ORIGIN/lib' "$BIN_DIR/freshclam"
fi

if [ ! -f "$DB_DIR/main.cvd" ]; then
  echo "Downloading virus definitions..."
  FRESHCLAM_CONF="$DB_DIR/freshclam.conf"
  cat > "$FRESHCLAM_CONF" <<EOF
DatabaseDirectory $DB_DIR
DatabaseMirror database.clamav.net
DNSDatabaseInfo current.cvd.clamav.net
UpdateLogFile $DB_DIR/freshclam.log
PIDFile $DB_DIR/freshclam.pid
EOF
  "$FRESHCLAM" --config-file="$FRESHCLAM_CONF" --datadir="$DB_DIR" 2>/dev/null || true

  if [ ! -f "$DB_DIR/main.cvd" ] && [ -d /var/lib/clamav ]; then
    echo "Copying system virus definitions..."
    cp /var/lib/clamav/*.cvd /var/lib/clamav/*.cld "$DB_DIR/" 2>/dev/null || true
  fi
fi

echo "Verifying bundled clamscan..."
"$BIN_DIR/clamscan" --version

echo "Linux ClamAV bundle ready in $BIN_DIR"
echo "Rebuild: npm run build"
