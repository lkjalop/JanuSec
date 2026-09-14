import time
import json
import pytest
from pathlib import Path

from fastapi.testclient import TestClient
from src.api.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    tele_path = tmp_path / 'telemetry.jsonl'
    undo_path = tmp_path / 'telemetry_undo.jsonl'
    monkeypatch.setenv('TELEMETRY_PATH', str(tele_path))
    monkeypatch.setenv('TELEMETRY_UNDO_PATH', str(undo_path))
    app = create_app()
    return TestClient(app)


def test_undo_token_flow(client):
    now = time.time()
    payload = [
        {'event_id': 'ux1', 'row_index': 11, 'disposition': 'benign', 'ts': now},
        {'event_id': 'ux2', 'row_index': 12, 'disposition': 'malicious', 'ts': now},
    ]
    r = client.post('/api/v1/telemetry/dispositions', json=payload)
    assert r.status_code == 200
    j = r.json()
    token = j.get('undo_token')
    assert token

    # preview
    pv = client.post('/api/v1/telemetry/preview_undo', json={'token': token})
    assert pv.status_code == 200
    pj = pv.json()
    assert pj['count'] == 2

    # metrics before undo
    m1 = client.get('/api/v1/telemetry/metrics').json()
    total_before = m1['by_disposition']['benign'] + m1['by_disposition']['malicious'] + m1['by_disposition']['needs_review']

    # undo
    u = client.post('/api/v1/telemetry/undo_with_token', json={'token': token})
    assert u.status_code == 200
    uj = u.json()
    assert len(uj.get('marked', [])) == 2

    # metrics after undo should not include these two
    m2 = client.get('/api/v1/telemetry/metrics').json()
    total_after = m2['by_disposition']['benign'] + m2['by_disposition']['malicious'] + m2['by_disposition']['needs_review']
    assert total_after == total_before - 2
