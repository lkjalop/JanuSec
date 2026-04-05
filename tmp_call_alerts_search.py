from fastapi.testclient import TestClient
from src.api.server import app, _ALERT_RING, _ALERT_RING_LOCK
import os, time
os.environ['ALERTS_API_KEYS']='testkey'
client = TestClient(app)
# prepare ring
with _ALERT_RING_LOCK:
    _ALERT_RING.clear()
from src.live import alert_store
now = time.time()
for i in range(3):
    rec = {'id': f'a{i}', 'ts': now + i, 'host': 'h1', 'verdict':'ALERT', 'score':0.9, 'rules':['r']}
    alert_store.append(rec)
    with _ALERT_RING_LOCK:
        _ALERT_RING.append(rec)
resp = client.get('/api/v1/alerts/search', headers={'X-API-Key':'testkey'}, params={'host':'h1'})
print('status', resp.status_code)
print('text', resp.text)
print('headers', resp.headers)
