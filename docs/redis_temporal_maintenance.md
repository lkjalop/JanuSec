# Redis Temporal Cache Maintenance (staging checklist)

This document explains how to enable the Redis temporal cache maintenance loop in staging and what environment variables are required.

Purpose
-------
The Redis temporal maintainer periodically calls `cleanup_hosts()` on the temporal cache to remove stale host entries from the Redis host set. This prevents unbounded growth of the host set.

How it is activated
-------------------
1. Ensure a Redis instance is available and reachable from the application.
2. Set the `REDIS_URL` environment variable to the Redis connection URL (e.g. `redis://:pass@10.0.0.5:6379/0`).
3. Enable the maintenance loop by setting `REDIS_TEMPORAL_MAINTENANCE_ENABLED=1` (or `true`).
4. Optionally set `REDIS_TEMPORAL_MAINTENANCE_INTERVAL` (in seconds). Default: 300.

Example (docker / k8s env):

```powershell
# Windows / Powershell example
$env:REDIS_URL = 'redis://localhost:6379/0'
$env:REDIS_TEMPORAL_MAINTENANCE_ENABLED = '1'
$env:REDIS_TEMPORAL_MAINTENANCE_INTERVAL = '300'

# Linux / container environment variables
# REDIS_URL=redis://redis.example.internal:6379/0 \
# REDIS_TEMPORAL_MAINTENANCE_ENABLED=1 \
# REDIS_TEMPORAL_MAINTENANCE_INTERVAL=300
```

Notes & safety
--------------
- The orchestrator only spawns the maintenance loop when `REDIS_URL` is set. The maintainer itself will exit immediately unless `REDIS_TEMPORAL_MAINTENANCE_ENABLED` is truthy.
- The maintainer performs best-effort cleanup and is safe to run concurrently across multiple orchestrator instances.
- Enable this in staging first and monitor `janusec_correlation_host_count` gauge (if Prometheus enabled) to validate host set sizes.

Troubleshooting
---------------
- If the maintainer doesn't start, ensure both `REDIS_URL` and `REDIS_TEMPORAL_MAINTENANCE_ENABLED` are set in the process environment that runs the orchestrator.
- Check logs for messages from `maintenance.redis_temporal_maintainer`.
