import os, json, time
os.environ['API_KEYS_JSON'] = json.dumps([{'key':'k3','scopes':['factors.search','recalibrator.admin']}])
# mimic test import order
from fastapi.testclient import TestClient
from src.api.server import app
from core.recalibrator import propose_and_write
from core.factor_attribution_store import FactorAttributionSnapshot, FACTOR_ATTRIBUTIONS
from core.labels_store import LABELS

client = TestClient(app)
# prepare samples
for i in range(60):
    eid = f'aa-{i}'
    snap = FactorAttributionSnapshot(event_id=eid, ts=time.time(), factors=['z'], breakdown=[{'factor':'z','contribution':0.6}], score=0.6, raw_score=0.58, confidence=0.9, variance=0.0, ci95=(0.5,0.7))
    FACTOR_ATTRIBUTIONS.add_snapshot(snap)
    LABELS.add_label(eid,'tp' if i%2==0 else 'fp','t')

p = propose_and_write(limit=200)
print('proposal', bool(p))
# build auth header
try:
    import jwt
    os.environ['JWT_SECRET']='test-jwt-secret'
    token = jwt.encode({'sub':'t','scopes':['factors.search']}, os.environ['JWT_SECRET'], algorithm='HS256')
    auth_hdr = {'Authorization': f'Bearer {token}'}
except Exception:
    auth_hdr = {'x-api-key':'k3'}

resp = client.post('/api/v1/risk/calibration/auto_accept', headers=auth_hdr)
print('STATUS', resp.status_code)
try:
    print('JSON', json.dumps(resp.json(), indent=2))
except Exception:
    print('TEXT', resp.text)

resp2 = client.post('/api/v1/risk/calibration/auto_accept?apply=true', headers=auth_hdr)
print('APPLY STATUS', resp2.status_code)
try:
    print('APPLY JSON', json.dumps(resp2.json(), indent=2))
except Exception:
    print('APPLY TEXT', resp2.text)
