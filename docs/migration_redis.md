# Migration to Redis Scheduler (Admin Guide)

1) Purpose: migrate from file-backed `data/enrichment_jobs.json` to Redis-backed scheduler.
2) Pre-checks:
   - Backup `data/enrichment_jobs.json` (git or copy)
   - Ensure Redis reachable and `ENABLE_REDIS_SCHEDULER=1` is set in env
3) Run migration:

```powershell
$env:ENABLE_REDIS_SCHEDULER='1'
$env:REDIS_URL='redis://127.0.0.1:6379/0'
python scripts/migrate_enrichment_jobs_to_redis.py
```

4) Verification:
   - Confirm `data/.redis_migrated` exists and contains migrated count.
   - Call admin endpoint `/api/v1/admin/enrichment/jobs` — should return `source: 'redis'` and job list.
5) Rollback:
   - If problems, stop scheduler and restore `data/enrichment_jobs.json` from backup.

*** End Patch