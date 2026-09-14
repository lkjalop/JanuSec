import asyncio
import pytest

from starlette.testclient import TestClient

import os

from src.api.server import app


class DummyConn:
    def __init__(self):
        self._rows = [
            {'session_id': 's1', 'user_info': {'email': 'a@example.com'}, 'created_at': '2025-01-01T00:00:00Z', 'expires_at': '2025-02-01T00:00:00Z', 'revoked': False},
            {'session_id': 's2', 'user_info': {'email': 'b@example.com'}, 'created_at': '2025-01-02T00:00:00Z', 'expires_at': '2025-02-02T00:00:00Z', 'revoked': False},
        ]
        self.execs = []

    async def fetch(self, q, *args):
        return self._rows

    async def fetchval(self, q, *args):
        # return total count for COUNT queries
        return len(self._rows)

    async def execute(self, q, *args):
        # mark revoked
        sid = args[0]
        for r in self._rows:
            if r['session_id'] == sid:
                r['revoked'] = True
        # capture executes for assertions (e.g., audit inserts)
        self.execs.append((q, args))
        return 'OK'


class DummyPool:
    def __init__(self):
        self.conn = DummyConn()

    def acquire(self):
        class CM:
            def __init__(self, conn):
                self.conn = conn
            async def __aenter__(self):
                return self.conn
            async def __aexit__(self, exc_type, exc, tb):
                return False
        return CM(self.conn)


@pytest.fixture(autouse=True)
def set_admin_token_env(monkeypatch):
    # ensure check_admin_token accepts our requests
    monkeypatch.setenv('ADMIN_UI_TOKEN', 'test-token')
    yield


def test_list_and_revoke(monkeypatch):
    pool = DummyPool()
    # patch the DB pool import used by server
    import types
    fake_db = types.SimpleNamespace(pool=pool)
    monkeypatch.setitem(__import__('sys').modules, 'db.adapter', fake_db)

    client = TestClient(app)
    from tests._helpers import admin_test_headers
    headers = admin_test_headers(client, admin_token='test-token')

    r = client.get('/api/v1/admin/sessions', headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert 'rows' in data
    assert any(rr['session_id'] == 's1' for rr in data['rows'])

    r2 = client.post('/api/v1/admin/sessions/s1/revoke', headers=headers)
    assert r2.status_code == 200
    assert r2.json().get('revoked') is True

    # verify that subsequent list shows revoked state
    r3 = client.get('/api/v1/admin/sessions', headers=headers)
    rows = r3.json()['rows']
    s1 = next(r for r in rows if r['session_id'] == 's1')
    assert s1['revoked'] is True

    # verify that an audit insert was attempted (by checking recorded executes)
    assert any('admin_session_audit' in q for q, a in pool.conn.execs)

    # test audit fetch endpoint (should return empty list since DummyConn.fetch returns rows list only for sessions)
    ra = client.get('/api/v1/admin/sessions/s1/audit', headers=headers)
    assert ra.status_code == 200
    assert 'rows' in ra.json()
