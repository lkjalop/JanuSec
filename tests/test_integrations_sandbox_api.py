import json
import os
from fastapi.testclient import TestClient

from src.api.app import app


def test_set_config_and_list_tasks(tmp_path):
    client = TestClient(app)

    cfg = {"api_url": "http://example.local:8090", "api_key": "abcd"}
    r = client.post('/api/v1/integrations/cuckoo/config', json=cfg)
    assert r.status_code == 200
    body = r.json()
    assert 'path' in body

    # list tasks (should return structure even if empty)
    r2 = client.get('/api/v1/admin/sandbox/tasks')
    assert r2.status_code == 200
    data = r2.json()
    assert 'count' in data and 'tasks' in data

    # schedule a refresh (won't error even if task is unknown)
    r3 = client.post('/api/v1/admin/sandbox/refresh', params={'task_id':'sim-123'})
    assert r3.status_code == 200
    assert r3.json().get('status') == 'refresh_scheduled'
