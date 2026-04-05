import os
import time
import sqlite3
from fastapi.testclient import TestClient

from src.api.app import app


def test_sqlite_session_insert_and_roundtrip(monkeypatch, tmp_path):
    db_path = tmp_path / 'sessions.db'
    monkeypatch.setenv('SESSION_BACKEND', 'sqlite')
    monkeypatch.setenv('SESSION_PERSIST_SQLITE_PATH', str(db_path))
    client = TestClient(app)

    r = client.post('/api/v1/graph/session/build', json={'session_ids':['A','B'], 'correlate':True})
    assert r.status_code == 200
    sid = r.json()['session_id']
    assert sid

    # Verify DB row exists
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute('SELECT id,json FROM sessions WHERE id=?', (sid,))
    row = cur.fetchone()
    conn.close()
    assert row is not None

    # Clear in-memory and load via GET
    from src.api.graph_sessions import _SESSIONS
    _SESSIONS.pop(sid, None)
    g = client.get(f'/api/v1/graph/session/{sid}')
    assert g.status_code == 200
    assert g.json().get('session_id') == sid


def test_sqlite_ttl_expiration(monkeypatch, tmp_path):
    db_path = tmp_path / 'sessions.db'
    monkeypatch.setenv('SESSION_BACKEND', 'sqlite')
    monkeypatch.setenv('SESSION_PERSIST_SQLITE_PATH', str(db_path))
    # Very short TTL
    monkeypatch.setenv('SESSION_TTL_SECONDS', '1')
    client = TestClient(app)

    r = client.post('/api/v1/graph/session/build', json={'session_ids':['X'], 'correlate':False})
    assert r.status_code == 200
    sid = r.json()['session_id']

    # Age the row by backdating updated_at
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    old = time.time() - 3600
    cur.execute('UPDATE sessions SET updated_at=? WHERE id=?', (old, sid))
    conn.commit()
    conn.close()

    # Clear in-memory and expect 404 due to TTL
    from src.api.graph_sessions import _SESSIONS
    _SESSIONS.pop(sid, None)
    g = client.get(f'/api/v1/graph/session/{sid}')
    assert g.status_code == 404

