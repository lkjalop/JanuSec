import os
import time
import psycopg2
import pytest
from urllib.parse import urlparse

@pytest.fixture(scope='session')
def postgres_dsn():
    return os.getenv('APP_DB_DSN', 'postgresql://test:test@localhost:5433/testdb')

@pytest.fixture(scope='session')
def pg_conn(postgres_dsn):
    p = urlparse(postgres_dsn)
    # wait for DB
    conn = None
    try:
        max_retries = int(os.getenv('APP_DB_CONN_RETRIES', '3'))
    except Exception:
        max_retries = 3
    try:
        retry_delay = float(os.getenv('APP_DB_CONN_DELAY', '0.1'))
    except Exception:
        retry_delay = 0.1
    for _ in range(max_retries):
        try:
            conn = psycopg2.connect(dbname=p.path.lstrip('/'), user=p.username, password=p.password, host=p.hostname, port=p.port)
            break
        except Exception:
            time.sleep(retry_delay)
    if conn is None:
        pytest.skip('Postgres not available')
    yield conn
    try:
        conn.close()
    except Exception:
        pass

@pytest.fixture(autouse=True)
def cleanup_db(pg_conn):
    # run before each test to ensure a clean slate for relevant tables
    cur = pg_conn.cursor()
    try:
        cur.execute("DELETE FROM admin_session_audit WHERE session_id LIKE 'itest%'")
        cur.execute("DELETE FROM admin_sessions WHERE session_id LIKE 'itest%'")
        pg_conn.commit()
    except Exception:
        pg_conn.rollback()
    yield
    # cleanup after
    try:
        cur.execute("DELETE FROM admin_session_audit WHERE session_id LIKE 'itest%'")
        cur.execute("DELETE FROM admin_sessions WHERE session_id LIKE 'itest%'")
        pg_conn.commit()
    except Exception:
        pg_conn.rollback()
