#!/usr/bin/env bash
# ClamAV smoke test: bundled scanner must detect the standard EICAR test file.
set -euo pipefail

CLAMSCAN="${1:?usage: ci-eicar-smoke.sh <clamscan> <database-dir>}"
DB_DIR="${2:?usage: ci-eicar-smoke.sh <clamscan> <database-dir>}"

if [ ! -x "$CLAMSCAN" ]; then
  echo "clamscan not executable: $CLAMSCAN"
  exit 1
fi

if [ ! -f "$DB_DIR/main.cvd" ] && [ ! -f "$DB_DIR/main.cld" ]; then
  echo "Skipping EICAR smoke test: virus database not present in $DB_DIR"
  exit 0
fi

EICAR_FILE="$(mktemp /tmp/null-threat-eicar.XXXXXX)"
# Standard EICAR test string (safe — not live malware)
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >"$EICAR_FILE"

set +e
"$CLAMSCAN" --no-summary --database="$DB_DIR" "$EICAR_FILE"
EXIT_CODE=$?
set -e
rm -f "$EICAR_FILE"

# clamscan exit 1 = infected found
if [ "$EXIT_CODE" -eq 1 ]; then
  echo "EICAR detected — ClamAV smoke test passed"
  exit 0
fi

echo "EICAR not detected (clamscan exit $EXIT_CODE) — smoke test FAILED"
exit 1
