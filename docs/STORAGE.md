# Storage & Persistence Configuration

This project supports multiple storage backends for assessment reports and session persistence.

Environment variables

- `STORAGE_BACKEND` - one of `memory`, `file`, `redis`, `postgres`. Defaults to `memory`.
- `DATABASE_URL` - Postgres DSN used when `STORAGE_BACKEND=postgres`.
- `REDIS_URL` / `REDIS_URI` - Redis connection URL used for caches, queues, and pub/sub.
- `SESSION_PERSIST_DIR` - File directory used by file-based session persistence (default: `data/assessments`).
- `MIGRATE_REPORT_STORE` - When set to `1`, `true`, or `yes` the server startup attempts to migrate any in-memory `REPORT_STORE` dicts into the configured backend.

Running migrations

- Ensure `alembic` is installed and `alembic.ini` is present at the repository root.
- Run migrations with the helper script:

```bash
python scripts/run_migrations.py
```

One-time migration

- To persist any existing in-memory `REPORT_STORE` entries into the configured backend, set:

```bash
export MIGRATE_REPORT_STORE=1
```

and start the server. The startup hook will attempt to locate `REPORT_STORE` dicts in common modules and persist them.

Local development

- For local/dev use `STORAGE_BACKEND=file` (default `SESSION_PERSIST_DIR` used).
- For CI, tests default to `memory` unless `DATABASE_URL` or `REDIS_URL` are provided.
