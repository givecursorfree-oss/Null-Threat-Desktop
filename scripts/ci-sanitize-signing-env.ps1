# Unset empty signing env vars so Tauri skips certificate import on unsigned CI builds.
foreach ($name in @(
    'WINDOWS_CERTIFICATE',
    'WINDOWS_CERTIFICATE_PASSWORD',
    'APPLE_CERTIFICATE',
    'APPLE_CERTIFICATE_PASSWORD',
    'APPLE_SIGNING_IDENTITY',
    'APPLE_ID',
    'APPLE_PASSWORD',
    'APPLE_TEAM_ID'
  )) {
  if (-not $env:$name) {
    Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
  }
}

if ($env:WINDOWS_CERTIFICATE) {
  Write-Host "Windows Authenticode signing enabled"
} else {
  Write-Host "Windows signing secrets not configured — unsigned build (SmartScreen may warn)"
}
