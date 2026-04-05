from fastapi.testclient import TestClient
import os

# Ensure test key set after TestClient creation as in failing test
from src.api.server import app, _ALERT_RING, _ALERT_RING_LOCK

client = TestClient(app)

# Mirror test behavior: set env in setup_method after TestClient created
os.environ['ALERTS_API_KEYS'] = 'testkey'

with _ALERT_RING_LOCK:
    _ALERT_RING.clear()

from src.live import alert_store
import time
now = time.time()
for i in range(3):
    rec = {'id': f'a{i}', 'ts': now + i, 'host': 'h1', 'verdict': 'ALERT', 'score': 0.9, 'rules': ['lolbin_misuse'], 'dest_ip': f'1.1.1.{i}'}
    alert_store.append(rec)
    with _ALERT_RING_LOCK:
        _ALERT_RING.append(rec)

r = client.get('/api/v1/alerts/search', headers={'X-API-Key':'testkey'}, params={'host':'h1'})
print('STATUS', r.status_code)
try:
    print('BODY', r.json())
except Exception:
    print('BODY TEXT', r.text)

# Also try without key to see behavior
r2 = client.get('/api/v1/alerts/search', params={'host':'h1'})
print('STATUS no key', r2.status_code)
try:
    print('BODY no key', r2.json())
except Exception:
    print('BODY no key TEXT', r2.text)
