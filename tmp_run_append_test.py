import os, time, json
os.environ['ALERTS_API_KEYS'] = 'testkey'
os.environ['ALERT_DEDUP_TTL_SECONDS'] = '1'
os.environ['ALERT_DEDUP_GRACE_SECONDS'] = '0.25'
os.environ['PYTEST_CURRENT_TEST'] = '1'
from fastapi.testclient import TestClient
from src.api.server import _ALERT_RING, _ALERT_RING_LOCK, app
client = TestClient(app)
BASE_EVENT = {
    'events': [
        {'id':'e1','host':'h1','proc_name':'powershell.exe','parent_proc':'winword.exe','dest_ip':'9.9.9.9'}
    ],
    'classify': True,
    'send_alerts': True,
    'include_rules': True
}
print('initial server_ring_id=', id(_ALERT_RING), 'len=', len(_ALERT_RING))
with _ALERT_RING_LOCK:
    _ALERT_RING.clear()
print('after clear server_ring_id=', id(_ALERT_RING), 'len=', len(_ALERT_RING))
# First alert
r1 = client.post('/api/v1/endpoints/log_batch', json=BASE_EVENT)
print('r1 status', r1.status_code, 'resp', r1.text)
print('after r1 server_ring_id=', id(_ALERT_RING), 'len=', len(_ALERT_RING))
# Duplicate inside TTL
r2 = client.post('/api/v1/endpoints/log_batch', json=BASE_EVENT)
print('r2 status', r2.status_code, 'resp', r2.text)
print('after r2 server_ring_len=', len(_ALERT_RING))
# Wait TTL expiry
time.sleep(1.2)
r3 = client.post('/api/v1/endpoints/log_batch', json=BASE_EVENT)
print('r3 status', r3.status_code, 'resp', r3.text)
print('after r3 server_ring_len=', len(_ALERT_RING))
# Print any module-level rings found
import sys
mods=[]
for m in list(sys.modules.values()):
    try:
        if getattr(m,'_ALERT_RING', None) is not None:
            mods.append((getattr(m,'__name__',str(m)), id(getattr(m,'_ALERT_RING')), len(getattr(m,'_ALERT_RING'))))
    except Exception:
        pass
print('module_rings_count=', len(mods))
for name,rid,ln in mods[:40]:
    print(name, rid, ln)
