 # No stray footer found to remove
from fastapi.testclient import TestClient
import os
import json
import time

# Ensure fast test mode is enabled before importing the app to skip heavy startup
os.environ['FAST_TEST_MODE'] = '1'
from src.api.server import app
from src.core.factor_attribution_store import FactorAttributionSnapshot, FACTOR_ATTRIBUTIONS
from src.core.labels_store import LABELS
from src.core.factor_stats_manager import FACTOR_STATS

# Ensure API keys env var is present before app/TestClient initialization
api_keys = [{'key':'testkey','scopes':['feedback.write','factors.search','risk.read']}]
os.environ['API_KEYS_JSON'] = json.dumps(api_keys)
client = TestClient(app)


def test_label_endpoint_and_status():
    # prepare a snapshot
    snap = FactorAttributionSnapshot(
        event_id='evt-api-1',
        ts=time.time(),
        factors=['api:f1'],
        breakdown=[{'factor':'api:f1','contribution':0.7}],
        score=0.7,
        raw_score=0.65,
        confidence=0.9,
        variance=0.0,
        ci95=(0.6,0.8),
    )
    FACTOR_ATTRIBUTIONS.add_snapshot(snap)
    # set API key with feedback.write scope via env API_KEYS_JSON
    api_keys = [{'key':'testkey','scopes':['feedback.write','factors.search']}]
    os.environ['API_KEYS_JSON'] = json.dumps(api_keys)
    # call label endpoint
    resp = client.post('/api/v1/decisions/evt-api-1/label', json={'label':'tp','source':'test'}, headers={'x-api-key':'testkey'})
    assert resp.status_code == 200
    j = resp.json()
    assert j['event_id'] == 'evt-api-1'
    # call status endpoint for factor
    resp2 = client.get('/api/v1/quality/factors/status/api:f1', headers={'x-api-key':'testkey'})
    assert resp2.status_code == 200
    s = resp2.json()
    assert s['factor'] == 'api:f1'
    assert s['tp'] >= 1


def test_calibration_export_api():
    # ensure one qualifying sample exists
    LABELS.add_label('evt-api-1','tp','t')
    # ensure testkey has risk.read scope (previous test may have narrowed it)
    api_keys_full = [{'key':'testkey','scopes':['feedback.write','factors.search','risk.read']}]
    os.environ['API_KEYS_JSON'] = json.dumps(api_keys_full)
    resp = client.get('/api/v1/risk/calibration/export', headers={'x-api-key':'testkey'})
    print('DEBUG_RESP_STATUS', resp.status_code)
    try:
        print('DEBUG_RESP_BODY', resp.json())
    except Exception:
        print('DEBUG_RESP_TEXT', resp.text)
    assert resp.status_code == 200
    js = resp.json()
    assert isinstance(js.get('samples'), list)
    # cleanup env
    os.environ.pop('API_KEYS_JSON', None)
 
