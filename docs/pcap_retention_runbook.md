# PCAP Retention & Runbook

- Retention policy: default 30 days; configurable per-tenant via `PCAP_RETENTION_DAYS`.
- Storage: store PCAPs under `data/pcaps/<tenant>/YYYY/MM/DD/` with lifecycle policies.
- Redaction: strip sensitive payloads before long-term storage; retain metadata (SNI, JA3, timestamps).
- Commands: rotate and prune older PCAPs

```powershell
# remove pcaps older than 30 days
Get-ChildItem -Path data\pcaps -Recurse -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -WhatIf
```

- Archival: move older PCAPs to cold storage (S3/Blob) with encrypted buckets.
- Compliance: maintain audit logs for PCAP access; redact PII before sharing externally.

*** End Patch