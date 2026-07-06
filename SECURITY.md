# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@nullthreat.dev** with:

1. Description of the issue
2. Steps to reproduce
3. Impact assessment (data exposure, RCE, privilege escalation, etc.)
4. Affected version and platform

We aim to respond within **48 hours** and will coordinate a fix before public disclosure.

## What we consider in scope

- Remote code execution via scan inputs, quarantine, or IPC
- Path traversal in file operations or quarantine restore
- Command injection in bundled scanner invocation
- Secrets or encryption key handling (OS keychain, quarantine AES-GCM)
- Supply-chain issues in release artifacts (unsigned installer tampering — verify checksums)

## Out of scope

- Detection misses (false negatives) in ClamAV/YARA/hash feeds — report to upstream feeds
- SmartScreen / Gatekeeper warnings on **unsigned** installers when checksums match the release
- Social engineering or physical access to an unlocked machine

## Secure defaults

- Scans run locally; no telemetry or cloud upload of file contents
- Optional hash and ClamAV updates fetch public threat feeds only when the user clicks update
- Quarantine keys prefer OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service)

## Verifying downloads

Every GitHub Release includes `SHA256SUMS.txt`. Verify before install:

```bash
sha256sum -c SHA256SUMS.txt
```

On Windows (PowerShell):

```powershell
Get-FileHash .\NullThreat_1.0.0_x64.msi -Algorithm SHA256
# Compare to the value in SHA256SUMS.txt
```

## Code signing

Signed Windows and macOS builds are produced when maintainer secrets are configured in CI. See [docs/CODE_SIGNING.md](docs/CODE_SIGNING.md). Unsigned builds are expected for community CI until certificates are added.

## Disclosure timeline

1. Reporter contacts security@nullthreat.dev
2. Maintainers confirm and assign severity
3. Fix developed and tested
4. Coordinated release and CVE (if applicable)
5. Public acknowledgment with credit to reporter (unless anonymous)
