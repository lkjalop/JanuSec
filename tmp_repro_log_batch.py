import os
os.environ['PYTEST_CURRENT_TEST']='1 (probe)'
from fastapi.testclient import TestClient
from src.api.server import app, _ALERT_RING, _ALERT_RING_LOCK
from src.api.alerts_endpoints import get_canonical_alert_ring, ALERT_RING as AE_RING
print('start ids', id(_ALERT_RING), id(AE_RING))
client = TestClient(app)
BASE_EVENT = {'events':[{'id':'evt-1','host':'h1','ts': 123, 'verdict':'malicious','score':0.95}]}
resp = client.post('/api/v1/endpoints/log_batch', json=BASE_EVENT)
print('status', resp.status_code)
print('after ids', id(_ALERT_RING), id(AE_RING))
print('len server ring', len(_ALERT_RING))
cr, cl, cm = get_canonical_alert_ring()
print('len canonical', len(cr), 'id', id(cr))
with _ALERT_RING_LOCK:
    print('server ring contents', list(_ALERT_RING))
