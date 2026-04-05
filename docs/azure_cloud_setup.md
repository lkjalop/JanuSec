# Azure Cloud Setup (Defender/Policy Continuous Export)

This guide covers a production-ready setup for streaming Azure Defender/Policy posture into the platform via Event Hub or Storage.

## Cloud Setup
- Export source: Enable Continuous Export for Defender/Policy to Event Hub or to Storage (Log Analytics as source). Confirm the export schemas match your tenants/subscriptions.
- Resource baseline:
  - Event Hub namespace + hub (streaming) OR Storage account + container (file export).
  - Key Vault for secret management.
  - Function App or Container App with Managed Identity (MI) to run the adapter.
- Access (least privilege): Assign to the MI only what’s needed:
  - Security Reader
  - Policy Insights Reader
  - Event Hubs Data Sender (if streaming) OR Storage Blob Data Reader (if storage export)

## Platform Config
- Tenant tagging: Choose either header `X-Tenant-ID` (recommended, multi-sub support) or static env `AZURE_DEF_SCHED_TENANT` for single-tenant workers. Document per-subscription → tenant mapping (e.g., subscriptionId → tenant label) in your deploy configs.
- API key: Issue a non-dev `x-api-key`. Rotate on a regular cadence and restrict egress by source IP/VNet or Private Link.
- Enable scheduler (file-based): Use `docker-compose.azure.override.yml` and set:
  - `AZURE_DEF_SCHED_DIR=/ingest/azure_defender`
  - `AZURE_DEF_SCHED_INTERVAL_SEC=60`
  - `AZURE_DEF_SCHED_BASE=http(s)://<platform>`
  - `AZURE_DEF_SCHED_API_KEY=...`
  - `AZURE_DEF_SCHED_TENANT=<tenant>` (optional)

## Event-Driven Function (recommended)
- Deploy `azure/functions/defender_eventhub` with an Event Hub trigger.
- App Settings:
  - `PLATFORM_API_BASE=https://<platform>`
  - `PLATFORM_API_KEY` (or `KEYVAULT_URI` + `SECRET_NAME` for Key Vault)
  - `TENANT_ID=<tenant>` or implement a mapping upstream
  - Optional tuning: `BATCH_MAX=1000`, `POST_MAX_RETRIES=5`, `PLATFORM_POST_TIMEOUT=10`
- host.json: Set `maxBatchSize` and concurrency limits to control cost/throughput.

## Transform & Data Quality
- Mapping coverage: The adapter normalizes `id`, `type`, `resource`, `severity` and preserves `source_ts` when present.
- Schema drift: See tests under `tests/fixtures/azure_defender/*` and `tests/test_azure_schema_assert.py` for asserts. Extend with real samples before deploy.
- Dedup keys: The platform dedupes by content. The adapters add `X-Idempotency-Key` per batch chunk derived from `(tenant, ids, resources, ts)`.

## Reliability
- Retries and DLQ: Function and scheduler both retry on 429/5xx with jitter and dead-letter failures to `artifacts/dlq/azure_defender.jsonl`.
- Backfill: Use `scripts/azure_backfill.py` to process historical exports in daily chunks. The script writes completion markers under `artifacts/backfill/azure_defender/YYYY-MM-DD.done`.
- Idempotency state: Event Hub trigger uses native checkpoints; file-based scheduler avoids reprocessing by mtime and the `.done` markers in backfill.

Note: The platform now includes a generic resilient ingestion helper and a writeback DLQ under `src/core/writeback_dlq.py`.
Operators can retry failed writebacks using `scripts/drain_writeback_dlq.py` which attempts to repost DLQ entries to `/api/v1/ingest/repair`.

## Security
- Secrets: Prefer Key Vault (Managed Identity). The Function resolves `PLATFORM_API_KEY` via `KEYVAULT_URI` + `SECRET_NAME` when configured.
- Network: Restrict egress to the platform (Private Link/Service Endpoints). TLS 1.2+ enforced; set `DEV_ALLOW_HTTP=1` only for local.
- Audit: The Function sends `X-Request-ID` per batch and logs tenant + request ID. Avoid PII in logs.

## Observability
- Metrics: Platform exposes ingest totals and lag via `/metrics`. Lag is computed from `source_ts` → ingest time.
- Alerts: See Grafana examples in `grafana/alert_rules.example.yaml` and dashboard `grafana/dashboards/azure_gap_lag.json`.
- Tracing: `X-Request-ID` correlates Function logs to platform ingestion.

## Performance & Scale
- Batching: Function posts in chunks (default up to 1000 findings per call).
- Rate limiting: 429/503 handled with exponential backoff and jitter. Host settings cap concurrency.
- Cost bounds: Tune `maxBatchSize`, memory, and timeouts. Add budget alerts in Azure Monitor.

## Quick Commands
```powershell
# File-based path (Windows dev):
docker compose -f docker-compose.yml -f docker-compose.azure.override.yml up -d

# Backfill daily chunks
python scripts/azure_backfill.py --dir C:\ingest\azure_defender --post https://localhost:8080 --api-key <key> --tenant <tid>

# DLQ replay
python scripts/dlq_replay.py --post https://localhost:8080 --api-key <key> --tenant <tid>
```
