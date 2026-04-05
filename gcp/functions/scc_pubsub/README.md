# GCP SCC Pub/Sub Worker

Processes Security Command Center notifications from Pub/Sub and posts normalized payloads to the platform compliance endpoints.

Environment variables:
- `PLATFORM_API_BASE` (required): Base URL to the platform (e.g., https://platform.example)
- `PLATFORM_API_KEY` (recommended via Secret Manager): API key for `x-api-key`
- `TENANT_ID` (optional): Fallback tenant id if mapping not resolved
- `TLS_ENFORCE` (optional, default 0): When `1`, require HTTPS endpoint
- `HTTP_TIMEOUT` (optional): Request timeout seconds
- `HTTP_MAX_RETRIES`, `HTTP_BACKOFF_BASE`: Tuning for retries
- `GCP_SCC_FUNC_DLQ_PATH` (optional): Local JSONL path for DLQ lines (in addition to Pub/Sub DLQ)

Deploy (example):
```bash
gcloud services enable cloudfunctions.googleapis.com pubsub.googleapis.com secretmanager.googleapis.com
gcloud functions deploy scc-pubsub-worker \
  --region=us-central1 \
  --runtime=python311 \
  --trigger-topic=scc-findings \
  --entry-point=pubsub_entry \
  --set-env-vars=PLATFORM_API_BASE=https://your.platform,TENANT_ID=your-tenant,TLS_ENFORCE=1 \
  --set-secrets=PLATFORM_API_KEY=projects/PROJECT_ID/secrets/platform-api-key:latest
```

Notes:
- Use a Pub/Sub dead-letter topic on the subscription to capture delivery failures.
- Restrict egress with Serverless VPC Access if needed; allow outbound to the platform.
- Idempotency and request tracing headers are set per batch.
```