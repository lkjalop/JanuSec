# Azure Ingestion Ops Runbook

## DLQ Replay / Inspect
- DLQ path (both Function and scheduler): `artifacts/dlq/azure_defender.jsonl` (override with `DLQ_PATH`).
- Replay tool: `scripts/dlq_replay.py`

Examples:
```bash
python scripts/dlq_replay.py --post https://platform.example --api-key $API_KEY --tenant corp-prod
```

## Backfill
- Historical exports: run `scripts/azure_backfill.py` to process files grouped by UTC day.
- Completion markers: written to `artifacts/backfill/azure_defender/YYYY-MM-DD.done` to avoid replays.

Examples:
```bash
python scripts/azure_backfill.py --dir /data/azure/exports --post https://platform.example --api-key $API_KEY --tenant corp-prod
```

## Pause / Resume per Tenant
- Recommended: pause at the source (Event Hub consumer or upstream rule). For file-based scheduler, stop setting `AZURE_DEF_SCHED_INTERVAL_SEC` > 0 or move files out temporarily.
- Optionally, set a deployment-level allowlist and pass only desired tenants via `X-Tenant-ID` from the worker.

## Key Rotation (Zero Downtime)
- Store API key in Key Vault as a versioned secret. Configure Function with `KEYVAULT_URI` and `SECRET_NAME`.
- Rotation flow:
  1) Add new secret version.
  2) Update platform to accept the new key.
  3) Restart Function/Container (or let it refresh) to pick new version.
  4) Revoke the old version once traffic is confirmed healthy.

## Troubleshooting Checklist
- Function logs include `X-Request-ID=<uuid>` per chunk. Use it to correlate platform requests.
- Verify `/metrics` has updated `posture_ingest_total{tenant}` and `posture_ingest_lag_seconds{tenant}`.
- Check Grafana dashboard `azure_gap_lag.json` for trends and gaps.
- On 429/503, the worker backs off with jitter. If persistent, reduce batch size or concurrency in `host.json`.
