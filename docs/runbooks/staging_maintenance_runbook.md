# Staging maintenance runbook: Redis temporal maintainer

Purpose
-------
Enable and validate the Redis temporal maintenance loop in staging. This loop removes stale host entries from the temporal cache host set and keeps Redis usage bounded.

Enable (docker-compose)
------------------------
1. Add the provided `docker-compose.override.yml` to your compose folder (it sets REDIS_URL and enables the maintainer).
2. Start services:

```powershell
docker compose up -d
```

Validate the maintainer started
------------------------------
1. Check logs for the maintainer bootstrap message:

```powershell
docker compose logs app | Select-String "Redis temporal cache maintenance loop"
```

2. You should see: "Starting Redis temporal cache maintenance loop (interval=300s)"

Validate Redis host-set size & metrics
------------------------------------
1. Prometheus: query host counts per tenant:

```
janusec_correlation_host_count{tenant="<tenant>"}

# Aggregate across tenants
sum(janusec_correlation_host_count)
```

2. Redis direct check (replace host/port if different):

```powershell
redis-cli -u "redis://localhost:6379" SCARD "janusec:correlation:hosts:<tenant>"
```

3. After a maintenance run you should see the SCARD decrease for stale hosts and Prometheus gauge reflect new counts.

Troubleshooting
---------------
- If maintainer doesn't start: ensure `REDIS_URL` is set in the process that starts the app and `REDIS_TEMPORAL_MAINTENANCE_ENABLED=1`.
- If Redis connection fails: verify network, credentials, and firewall rules to Redis host.
- If counts do not drop: the host keys may still exist (TTL not expired) — verify per-host key TTLs and consider lowering `REDIS_TEMPORAL_MAINTENANCE_INTERVAL` for testing.

Rollout guidance
-----------------
- Recommend enabling maintainer in a single orchestrator replica in production to reduce duplicated cleanup work.
- For small clusters or low ingest, enabling on all replicas is acceptable because the maintainer is idempotent.
