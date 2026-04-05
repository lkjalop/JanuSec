from fastapi.testclient import TestClient
import os, json, time

import os
os.environ['PLATFORM_LITE_INIT'] = '1'
from src.api.app import app


def test_ingestion_record_and_health(tmp_path, monkeypatch):
    # avoid background startup tasks by forcing lite init
    monkeypatch.setenv('PLATFORM_LITE_INIT', '1')
    # point SESSION_PERSIST_DIR to tmp to avoid polluting repo
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(tmp_path))
    client = TestClient(app)
    # record an event
    r = client.post('/api/v1/health/ingestion/record/testsrc')
    assert r.status_code == 200
    assert r.json().get('status') == 'recorded'
    # check summary
    r2 = client.get('/api/v1/health/ingestion')
    assert r2.status_code == 200
    j = r2.json()
    assert 'summary' in j
    assert 'ewma_counts' in j['summary']
    # check per-source last seen
    r3 = client.get('/api/v1/health/ingestion/testsrc')
    assert r3.status_code == 200
    assert r3.json().get('source') == 'testsrc'
