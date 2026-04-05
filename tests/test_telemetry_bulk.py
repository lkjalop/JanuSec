import time
import json
from pathlib import Path

import pytest

from fastapi.testclient import TestClient

from src.api.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Ensure telemetry path is under tmp_path for test isolation
    tele_path = tmp_path / 'telemetry.jsonl'
    monkeypatch.setenv('TELEMETRY_PATH', str(tele_path))
    app = create_app()
    client = TestClient(app)
    return client


def test_bulk_dispositions_and_metrics(client):
    now = time.time()
    payload = [
        {'event_id': 'e1', 'row_index': 1, 'disposition': 'benign', 'ts': now},
        {'event_id': 'e2', 'row_index': 2, 'disposition': 'malicious', 'ts': now},
        {'event_id': 'e3', 'row_index': 3, 'disposition': 'needs_review', 'ts': now},
    ]
    resp = client.post('/api/v1/telemetry/dispositions', json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get('ok') is True
    assert isinstance(data.get('ids'), list) and len(data['ids']) == 3

    # metrics
    m = client.get('/api/v1/telemetry/metrics')
    assert m.status_code == 200
    mm = m.json()
    assert mm['total_dispositions'] >= 3
    by_disp = mm['by_disposition']
    assert by_disp['benign'] >= 1
    assert by_disp['malicious'] >= 1

    # recent
    r = client.get('/api/v1/telemetry/recent?limit=10')
    assert r.status_code == 200
    rr = r.json()
    assert rr['count'] >= 3
