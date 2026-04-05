# Google SCC Ingestion (Production Guide)

This guide covers both scheduled-export and event-driven (recommended) ingestion for Google Security Command Center (SCC).

## Scheduled Exports (File-based)

- Enable the built-in scheduler in `src/api/app.py` by setting:
  - `GCP_SCC_SCHED_DIR`, `GCP_SCC_SCHED_INTERVAL_SEC`, `GCP_SCC_SCHED_BASE`, `GCP_SCC_SCHED_API_KEY`, `GCP_SCC_SCHED_TENANT`.
- Adapter: `scripts/gcp_scc_to_posture.py` (retries, idempotency, TLS guard, DLQ).
- Quick start: use `docker-compose.gcp.override.yml`, drop JSON exports under `./data/gcp_scc_exports`.

## Event-Driven (Recommended)

- SCC Notification → Pub/Sub → Cloud Function `scc-pubsub-worker`.
- Create Pub/Sub with DLQ and deploy (adjust project/region/secrets):
```bash
PROJECT_ID=your-project
REGION=us-central1
TOPIC=scc-findings
SUB=scc-findings-sub
DLQ=scc-findings-dlq
SECRET_NAME=platform-api-key

# Create Pub/Sub (with DLQ)
./scripts/gcp_scc_pubsub_setup.sh $PROJECT_ID $TOPIC $SUB $DLQ

gcloud services enable cloudfunctions.googleapis.com pubsub.googleapis.com secretmanager.googleapis.com
# Deploy function (uses Secret Manager for PLATFORM_API_KEY)
./scripts/gcp_scc_deploy_function.sh $PROJECT_ID $REGION scc-pubsub-worker $TOPIC https://your.platform your-tenant $SECRET_NAME
```

## Security
- Workload Identity, no static keys.
- Secret Manager for API key; rotate secrets and audit access. If using Cloud Functions secret env var bindings, prefer `:latest` but consider redeploy or runtime fetch (set `PLATFORM_API_KEY_SECRET` and the worker fetches via Secret Manager) to pick up rotations without redeploy.
- Restrict egress via Serverless VPC Access; allow platform endpoint.

## Observability
- Platform metrics: ingest totals and lag (`source_ts`).
- Optionally export worker counters: success/fail totals, retries, DLQ size.
- Dashboards/alerts: mirror Azure lag p90, error rate, DLQ growth; route to Slack/Teams.

## Reliability & Ops
- DLQ: use Pub/Sub DLQ and optional JSONL (`GCP_SCC_FUNC_DLQ_PATH`).
- Replay: `scripts/gcp_scc_dlq_replay.py`.
- Backfill: `scripts/gcp_scc_backfill.py` with completion markers & throttling.

## Testing & CI
- Unit tests for mapping (e.g., `tests/test_gcp_scc_schema_assert.py`).
- Pub/Sub roundtrip test in a test project.
- Load tests with synthetic batches.

## Validation
- Publish a test SCC finding to Pub/Sub topic:
```bash
./scripts/gcp_scc_publish_sample.sh $PROJECT_ID $TOPIC
```
- Confirm platform `/metrics` (posture_ingest_total, posture_ingest_lag_seconds) and Grafana panels update.
- Verify DLQ stays flat and error-rate alerts do not fire.

## Alert Routing (Slack/Teams)
- Import rules from `grafana/alert_rules.gcp_scc.example.yaml`.
- In Grafana Alerting, create Contact Points for Slack/Teams (webhook URLs) and tie them to these rules.
- Optionally add templates to include tenant, lag p90, and DLQ growth in messages.

## Tenant Mapping & Pause Controls
- Provide `TENANT_MAPPING_JSON` pointing to a JSON file like:
```json
{
  "projects": { "my-gcp-project": "tenant-a" },
  "default_tenant": "tenant-a"
}
```
- Allowlist/pause via envs: `TENANT_ALLOWLIST=tenant-a,tenant-b`, `TENANT_PAUSE_LIST=tenant-c`.
- The worker enforces these before posting to the platform.

## Performance Tuning
- Tune retries/backoff via envs: `HTTP_MAX_RETRIES`, `HTTP_BACKOFF_BASE`, `HTTP_TIMEOUT`.
- Observe retry counts and DLQ; increase concurrency by scaling min/max instances for Cloud Functions (2nd gen) or move to Cloud Run if higher throughput is needed.

### Windows (PowerShell) metrics check
```powershell
$headers = @{ 'x-api-key' = 'devkey123' }
Invoke-RestMethod -Method GET -Uri http://localhost:8080/metrics -Headers $headers | Out-String | Select-String -Pattern "posture_ingest_total|posture_ingest_lag_seconds"
```
