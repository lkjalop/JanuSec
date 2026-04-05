Local Postgres & Migrations
===========================

Quick steps to spin up a local Postgres and apply DB migrations for development:

- Start Postgres via Docker Compose:

  docker compose -f docker-compose.dev.yml up -d

- Ensure env vars point to the DB (optional, defaults are provided by compose):

  export APP_DB_DSN=postgresql://postgres:postgres@localhost:5432/janusec

- Run Alembic migrations:

  python scripts/run_smoke_migration.py --db $APP_DB_DSN

- Alternatively, POST to the admin migration endpoint (requires admin RBAC and ADMIN_TRIGGER_MIGRATIONS=1):

  POST /api/v1/admin/db/migrate  {"confirm":true}

Notes
- The endpoint executes the Alembic runner as a subprocess and is gated by the
  ADMIN_TRIGGER_MIGRATIONS environment variable to prevent accidental runs.

Convenience
-----------

You can bring up Postgres and run migrations with:

```
make up-migrate
```

CI
--

A GitHub Actions workflow `.github/workflows/migrations-and-db-tests.yml` runs migrations
against a temporary Postgres and then runs `tests/test_db_smoke.py` to verify the
`alembic_version` table exists.
