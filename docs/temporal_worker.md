Temporal Worker
================

Overview
--------
The temporal worker polls `temporal_tasks`, evaluates deferred DSL temporal/stat rules, and creates deduplicated incidents.

Quick Start
-----------
- Ensure migrations (including `temporal_tasks`) are applied and `events` table exists.
- Set `JNS_DB_DSN` to point to your Postgres instance.
- Start the worker:

```powershell
python -m src.workers.temporal_worker
```

Configuration (env)
-------------------
- `JNS_DB_DSN` — Postgres DSN (required).
- `TEMPORAL_WORKER_POLL` — poll interval in seconds (default `1.0`).
- `TEMPORAL_METRICS_PORT` — Prometheus metrics port (default `8000`).
- `TEMPORAL_WORKER_RETRIES` — DB retry count (default `3`).
- `TEMPORAL_WORKER_BACKOFF` — base backoff seconds (default `0.2`).
- `TEMPORAL_WORKER_LOG_LEVEL` — logging level (INFO/DEBUG).

Supervisor
----------
- systemd unit example: `scripts/temporal_worker.service`
- Windows service installer: `scripts/install_temporal_worker_service.ps1`

Notes
-----
- Incident deduplication uses a stable fingerprint of canonical event fields (sha256 truncated) plus minute window. You can tune TTL by changing key composition in the worker.
- Metrics are exposed on `TEMPORAL_METRICS_PORT` via the `prometheus_client` HTTP server.
