import time
import os
import json
import sqlite3
import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.dispatch_outbox import DB_PATH


client = TestClient(app)


def _read_outbox_rows():
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, tenant_id, endpoint, payload, attempts, status FROM outbox')
    rows = cur.fetchall()
    conn.close()
    return rows


def test_outbox_enqueue_and_worker_runs():
    # call dispatch with unsupported endpoint to force enqueue
    payload = {'ask': {'api': {'endpoint': 'unsupported_service'}, 'id': 'test-outbox-1'}, 'dispatch_id': 'test-outbox-1'}
    # Dispatch should attempt and then enqueue to outbox
    r = client.post('/api/v1/gaps/dispatch', json=payload, headers={'x-api-key': 'devkey123'})
    assert r.status_code in (200, 400, 500)
    # Give a moment for enqueue to be written
    time.sleep(0.2)
    rows = _read_outbox_rows()
    # Expect the outbox entry for our id
    ids = [r[0] for r in rows]
    assert 'test-outbox-1' in ids
