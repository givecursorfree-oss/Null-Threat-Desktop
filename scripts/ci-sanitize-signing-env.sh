#!/usr/bin/env bash
# GitHub Actions sets missing secrets to empty strings, which breaks Tauri signing import.
# Unset any empty signing variable so unsigned/ad-hoc builds succeed.
for var in \
  APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY \
  APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID; do
  eval "val=\${$var:-}"
  if [ -z "$val" ]; then
    unset "$var" 2>/dev/null || true
  fi
done

if [ -n "${APPLE_CERTIFICATE:-}" ]; then
  echo "Apple Developer ID signing enabled"
else
  echo "Apple signing secrets not configured — ad-hoc macOS build"
fi
