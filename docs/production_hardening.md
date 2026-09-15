# Production Hardening Checklist (Enrichment + Scheduler)

- Secrets & config
  - Store any API keys (KEV/EPSS) in a secrets manager, not in repo.
  - Use `REDIS_URL` with auth and TLS for production Redis.
- Connection pooling
  - Use connection pools for Redis and external enrichment clients.
- Circuit breakers & retries
  - Wrap external calls (EPSS/KEV) with circuit-breaker, exponential backoff and jitter.
- Monitoring & metrics
  - Export Prometheus metrics for scheduler job runs, migration count, rate-drops, errors.
  - Set alerts for job failures and rate-drop spikes.
- SLOs
  - Define SLOs for enrichment latency (e.g., cached hits <100ms, live fetch <500ms p95).
- Backups & recovery
  - Backup `data/enrichment_jobs.json` and Redis persistence files (if using RDB/AOF).
- Security
  - Restrict Redis to internal network; use TLS and client auth when exposed.

*** End Patch