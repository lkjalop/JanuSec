import os
import json
from fastapi.testclient import TestClient

from src.api.csv_backfill import router as backfill_router, PERSIST_DIR
from fastapi import FastAPI

app = FastAPI()
app.include_router(backfill_router)

client = TestClient(app)

def test_start_and_status_and_stop(tmp_path, monkeypatch):
    aid = 'test-assessment-123'
    # ensure clean persist dir
    tmpdir = tmp_path / 'backfill'
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(tmpdir))
    # create client with patched env by reimporting module
    # Start backfill
    resp = client.post('/api/v1/csv/deep_analyze/auto_backfill', json={'assessment_id': aid, 'total_rows': 10})
    assert resp.status_code == 200
    j = resp.json()
    assert j.get('ok') is True
    # status should exist
    resp2 = client.get(f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/status')
    assert resp2.status_code == 200
    st = resp2.json()
    assert st.get('state') == 'running'
    # stop
    resp3 = client.post(f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/stop')
    assert resp3.status_code == 200
    resp4 = client.get(f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/status')
    assert resp4.status_code == 200
    st2 = resp4.json()
    assert st2.get('state') == 'stopped'
