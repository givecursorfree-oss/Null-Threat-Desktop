# Hash Databases

Null Threat uses local SQLite tables (`nsrl`, `malwarebazaar`) inside the app database for Layer 1 hash lookups.

## MalwareBazaar (known malware)

1. Download the daily CSV export (no API key required):
   https://bazaar.abuse.ch/export/txt/sha256/recent/
2. Import hashes into the `malwarebazaar` table:

```sql
INSERT OR REPLACE INTO malwarebazaar (sha256, threat_name)
VALUES ('<sha256>', '<malware_family>');
```

Or use the in-app **Settings → Signature Updates** flow once implemented.

## NSRL (known-good reference)

The NIST NSRL RDS is large. For development, seed a small subset of known-good hashes:

```sql
INSERT OR REPLACE INTO nsrl (sha256, product_name)
VALUES ('<sha256>', 'Windows System File');
```

Production deployments should import the NSRL SHA-256 subset from your licensed NSRL export.

## Notes

- Pre-built `.db` files in this folder are optional; the app creates tables on first launch.
- Hash databases are gitignored — build them locally from bulk exports.
