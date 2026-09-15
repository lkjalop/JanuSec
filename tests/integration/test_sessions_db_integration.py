import os
import pytest
import psycopg2.extras
from starlette.testclient import TestClient

from src.api.server import app


@pytest.mark.skipif(os.getenv('CI') is None, reason='integration tests require CI/docker env or manual run')
def test_sessions_db_flow(pg_conn, postgres_dsn):
    cur = pg_conn.cursor()
    # ensure migrations created tables
    cur.execute("SELECT to_regclass('public.admin_sessions')")
    assert cur.fetchone()[0] is not None
    # insert session row
    cur.execute("INSERT INTO admin_sessions(session_id, user_info, created_at, expires_at, revoked) VALUES(%s,%s, NOW(), NOW()+INTERVAL '1 day', false)", ('itest1', psycopg2.extras.Json({'email':'i@example.com'})))
    pg_conn.commit()
    client = TestClient(app)
    # set ADMIN_UI_TOKEN to avoid OIDC flow
    os.environ['ADMIN_UI_TOKEN'] = 'itoken'
    from tests._helpers import admin_test_headers
    hdrs = admin_test_headers(client, admin_token='itoken')
    r = client.get('/api/v1/admin/sessions', headers=hdrs)
    assert r.status_code == 200
    data = r.json()
    assert any(r['session_id']=='itest1' for r in data['rows'])
    # revoke
    rr = client.post('/api/v1/admin/sessions/itest1/revoke', headers=hdrs)
    assert rr.status_code == 200
    # audit present
    cur.execute("SELECT session_id, action FROM admin_session_audit WHERE session_id=%s", ('itest1',))
    rows = cur.fetchall()
    assert any(r[1]=='revoke' for r in rows)
