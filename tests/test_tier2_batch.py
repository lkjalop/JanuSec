import time
import json
from fastapi.testclient import TestClient

from src.api.app import create_app
app = create_app({'mode': 'test'})


def test_tier2_batch_smoke():
    client = TestClient(app)
    rows = [{'row_index': 0, 'raw': {'process_name': 'cmd.exe', 'host': 'host1', 'verdict': 'suspicious', 'factors': ['lolbin']}}]
    resp = client.post('/api/v1/insights/tier2/enrich_batch', json={'assessment_id': 'test', 'rows': rows})
    assert resp.status_code == 200
    j = resp.json()
    assert 'rows' in j and isinstance(j['rows'], list)
    assert j['rows'][0].get('payload') is not None
