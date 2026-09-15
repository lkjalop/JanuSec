import os
import json
import time
from fastapi.testclient import TestClient
from src.api.server import app
from core.recalibrator import propose_and_write, LAST_PROPOSAL, PROPOSAL_HISTORY

client = TestClient(app)


def test_recalibrator_endpoints():
    # ensure no proposal initially
    # Disable tenant rate limiting for this unit test to avoid incidental 429s
    # when running the full suite in batches.
    os.environ['TENANT_RATE_LIMIT_ENABLED'] = '0'
    os.environ['API_KEYS_JSON'] = json.dumps([{'key':'k','scopes':['factors.search']}])
    # generate a fake proposal directly
    p = propose_and_write(limit=0)  # will return None when no samples
    # calling last should succeed even if None
    resp = client.get('/api/v1/risk/calibration/last', headers={'x-api-key':'k'})
    assert resp.status_code == 200
    j = resp.json()
    assert 'proposal' in j
    # call history endpoint
    resp2 = client.get('/api/v1/risk/calibration/history', headers={'x-api-key':'k'})
    assert resp2.status_code == 200
    h = resp2.json()
    assert 'history' in h
