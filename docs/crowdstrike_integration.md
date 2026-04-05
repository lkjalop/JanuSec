# CrowdStrike Integration (Demo -> Production Path)

This document describes the lightweight CrowdStrike connector provided for demo and staging use. It implements OAuth2 token exchange with a local disk cache, a paged fetch example, and a simple background sync loop.

Configuration (env vars)
- `CROWDSTRIKE_CLIENT_ID` - OAuth2 client id (optional for demo)
- `CROWDSTRIKE_CLIENT_SECRET` - OAuth2 client secret (optional for demo)
- `CROWDSTRIKE_BASE_URL` - CrowdStrike API base URL (default: https://api.crowdstrike.com)
- `CROWDSTRIKE_TOKEN_CACHE` - Path to store token cache (default: `.cs_token.json` in current working dir)
- `CROWDSTRIKE_SYNC_INTERVAL_SECONDS` - If >0, enables a background sync loop that polls CrowdStrike every N seconds (demo only)
- `CROWDSTRIKE_BACKFILL_SECONDS` - When first running, backfill window in seconds (default: 3600)

Security notes
- The token cache is stored on disk to avoid frequent token fetches. The connector attempts to set safe file permissions when writing the cache, but on Windows this may be limited. Ensure the token cache file is accessible only to the service account running the process.
- For production, prefer using a secure secrets store (Vault, AWS Secrets Manager, KeyVault) and a redis-backed sync worker instead of local disk caching.

Production recommendations
- Implement robust paging, rate-limit handling, retry/backoff, and idempotent ingestion.
- Use a centralized scheduler (e.g., celery beat, systemd timer, or Kubernetes CronJob) for polling rather than in-process loops for resilience.
- Persist vendor payloads to a decision store (Postgres/Redis) and limit raw payload size to avoid memory blowup.
