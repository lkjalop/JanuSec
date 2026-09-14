import os, json, time
from fastapi.testclient import TestClient
from src.api.server import app
from core.factor_attribution_store import FactorAttributionSnapshot, FACTOR_ATTRIBUTIONS
from core.labels_store import LABELS
from core.recalibrator import propose_and_write

os.environ['API_KEYS_JSON'] = json.dumps([{'key': 'k3', 'scopes': ['factors.search', 'recalibrator.admin']}])
client = TestClient(app)

# prepare samples
for i in range(60):
    eid = f'dbg-aa-{i}'
    snap = FactorAttributionSnapshot(event_id=eid, ts=time.time(), factors=['z'], breakdown=[{'factor':'z','contribution':0.6}], score=0.6, raw_score=0.58, confidence=0.9, variance=0.0, ci95=(0.5,0.7))
    FACTOR_ATTRIBUTIONS.add_snapshot(snap)
    LABELS.add_label(eid,'tp' if i%2==0 else 'fp','t')

p = propose_and_write(limit=200)
print('proposal', p)
resp = client.post('/api/v1/risk/calibration/auto_accept', headers={'x-api-key':'k3'})
print('status', resp.status_code)
print('body', resp.text)
