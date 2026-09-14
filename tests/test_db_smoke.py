import os
import psycopg2
import pytest


def test_alembic_version_table_exists():
    if os.getenv('DISABLE_DB', '0').lower() in {'1', 'true', 'yes'}:
        pytest.skip('Database disabled by DISABLE_DB')
    dsn = os.getenv('APP_DB_DSN') or 'postgresql://postgres:postgres@localhost:5432/janusec'
    try:
        conn = psycopg2.connect(dsn)
    except psycopg2.OperationalError:
        pytest.skip('Postgres not available for db smoke test')
    cur = conn.cursor()
    cur.execute("SELECT to_regclass('public.alembic_version')")
    res = cur.fetchone()[0]
    conn.close()
    assert res is not None, 'alembic_version table should exist after migrations'
