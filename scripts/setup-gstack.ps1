# Sync gstack Cursor skills into this repo from the global install.
# Requires: git, bun, gstack cloned to $env:USERPROFILE\.cursor\skills\gstack

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$GstackRepo = Join-Path $env:USERPROFILE ".cursor\skills\gstack"
$Generated = Join-Path $GstackRepo ".cursor\skills"
$ProjectSkills = Join-Path $Root ".cursor\skills"

if (-not (Test-Path $Generated)) {
    Write-Error "gstack not built. Run: cd `"$GstackRepo`" && bun install && bun run gen:skill-docs --host cursor"
}

New-Item -ItemType Directory -Force -Path $ProjectSkills | Out-Null

Get-ChildItem $Generated -Directory | Where-Object { $_.Name -like "gstack*" -and $_.Name -ne "gstack" } | ForEach-Object {
    $dest = Join-Path $ProjectSkills $_.Name
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Copy-Item -Recurse -Force $_.FullName $dest
}

$ProjectRuntime = Join-Path $ProjectSkills "gstack"
if (Test-Path $ProjectRuntime) { Remove-Item -Recurse -Force $ProjectRuntime }
cmd /c mklink /J "`"$ProjectRuntime`"" "`"$GstackRepo`"" | Out-Null

Copy-Item -Force (Join-Path $Generated "gstack\SKILL.md") (Join-Path $GstackRepo "SKILL.md")

Write-Host "gstack skills synced to $ProjectSkills"
