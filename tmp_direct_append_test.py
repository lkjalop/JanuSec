import os, time
os.environ['PYTEST_CURRENT_TEST'] = '1'
os.environ['ALERTS_API_KEYS'] = 'testkey'
os.environ['ALERT_DEDUP_TTL_SECONDS'] = '1'
# Avoid heavy app init: import append_alert and server ring directly
from src.api.server import _ALERT_RING, _ALERT_RING_LOCK
from src.api.alerts_endpoints import append_alert, get_tenant_alert_path
print('before id,len:', id(_ALERT_RING), len(_ALERT_RING))
with _ALERT_RING_LOCK:
    _ALERT_RING.clear()
print('cleared id,len:', id(_ALERT_RING), len(_ALERT_RING))
alert = {'id':'e1','ts': time.time(), 'host':'h1', 'tenant_id': None}
append_alert(alert)
print('after append id,len:', id(_ALERT_RING), len(_ALERT_RING))
# show contents
with _ALERT_RING_LOCK:
    for i, a in enumerate(_ALERT_RING):
        print(i, a)
