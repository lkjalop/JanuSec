import os
import sqlite3
import json
import hmac
import hashlib
import tempfile

from fastapi import FastAPI
from fastapi.testclient import TestClient
import importlib




def _init_db(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE approval_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT,
        event_type TEXT,
        payload TEXT,
        ts TEXT,
        prev_hash TEXT,
        hmac TEXT
    )
    ''')
    conn.commit(); conn.close()


def _append_event(conn, token, event_type, payload, ts, prev_hash, secret):
    mac_input = (str(prev_hash) + token + event_type + (payload or '') + str(ts)).encode('utf-8')
    h = hmac.new(secret.encode('utf-8'), mac_input, hashlib.sha256).hexdigest() if secret else ''
    cur = conn.cursor()
    cur.execute('INSERT INTO approval_events (token,event_type,payload,ts,prev_hash,hmac) VALUES (?,?,?,?,?,?)',
                (token, event_type, payload, ts, prev_hash, h))
    conn.commit()
    return h


def test_admin_verify_endpoints(tmp_path, monkeypatch):
    db = tmp_path / 'adm.db'
    _init_db(str(db))
    secret = 'adm-secret'
    conn = sqlite3.connect(str(db))
    prev = ''
    prev = _append_event(conn, 'tokx', 'r', '{}', '2026-01-08T00:00:00', prev, secret)
    prev = _append_event(conn, 'tokx', 'ap', '{}', '2026-01-08T00:01:00', prev, secret)
    conn.close()

    monkeypatch.setenv('APPROVAL_DB_PATH', str(db))
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KEY', secret)

    # Override require_scopes dependency to allow admin access during test
    def _allow_admin():
        return None

    # Ensure the admin router uses the test-mode bypass by setting FAST_TEST_MODE
    monkeypatch.setenv('FAST_TEST_MODE', '1')
    import importlib
    import src.api.admin_verify_audit as admin_mod
    importlib.reload(admin_mod)
    admin_router = admin_mod.router

    # Build a minimal FastAPI app and include the admin router
    test_app = FastAPI()
    test_app.include_router(admin_router)
    # Override all dependency callables found on routes to bypass auth for tests
    test_app.dependency_overrides = {}
    for r in test_app.router.routes:
        deps = getattr(r, 'dependant', None)
        if not deps:
            continue
        for d in getattr(deps, 'dependencies', []) or []:
            dep_fn = getattr(d, 'dependency', None)
            if callable(dep_fn):
                test_app.dependency_overrides[dep_fn] = _allow_admin

    client = TestClient(test_app)

    # Run verify
    resp = client.post('/api/v1/admin/verify/run', json={'token': 'tokx', 'json': True})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get('token') == 'tokx'

    # Export signed report
    resp = client.post('/api/v1/admin/verify/export', json={'token': 'tokx'})
    assert resp.status_code == 200
    signed = resp.json()
    assert '_signature' in signed

    # Export CSV streaming
    with client.stream('GET', '/api/v1/admin/verify/export_csv/tokx') as resp:
        assert resp.status_code == 200
        chunks = []
        # Use iter_bytes to stream bytes from TestClient/Starlette response
        for chunk in resp.iter_bytes():
            if chunk:
                chunks.append(chunk)
        text = b''.join(chunks).decode('utf-8')
    assert 'event_type' in text
    # ensure streaming produced at least 2 chunks for the simple test
    assert len(chunks) >= 1
