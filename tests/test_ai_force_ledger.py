import json
import time

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.core.metrics.cost_ledger import get_cost_ledger


def test_force_external_records_ledger(tmp_path):
    app = create_app()
    client = TestClient(app)
    # Ensure starting state
    ledger = get_cost_ledger()
    before = len(ledger.records)

    headers = {'x-api-key': 'devkey123', 'content-type':'application/json'}
    payload = {'provider':'openai','tenant':'test_tenant','mock':True,'text':'pytest force test'}
    resp = client.post('/api/v1/ai/force_external', headers=headers, json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert 'tokens_used' in data
    # Allow small window
    time.sleep(0.05)
    after = len(ledger.records)
    assert after >= before + 1
