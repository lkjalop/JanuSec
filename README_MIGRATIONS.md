Migrations (Alembic)
---------------------

This project uses Alembic for DB migrations. The Alembic configuration lives in `migrations/alembic` and revision scripts in `migrations/alembic/versions`.

To run migrations locally (ensure `APP_DB_DSN` env var is set):

```bash
export APP_DB_DSN=postgresql://user:pass@host:5432/dbname
python -m alembic upgrade head
```

CI systems should run the same `alembic upgrade head` step before running tests.
