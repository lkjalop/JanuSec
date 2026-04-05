import os
os.environ['PYTEST_CURRENT_TEST']='1 (probe)'
from fastapi.testclient import TestClient
from src.api.server import app, _process_endpoint_event, LogBatchContext, _RUNTIME, LogEvent, _ALERT_RING, _ALERT_RING_LOCK
print('before ring len', len(_ALERT_RING))
client = TestClient(app)
BASE_EVENT = {'id':'e1','host':'h1','proc_name':'powershell.exe'}
# call internal processor
import asyncio
ctx = LogBatchContext(runtime=_RUNTIME, include_rules=True, classify=True, send_alerts=True, tenant_id=None, nx_enabled=False, dedup_ttl=1.0)
print('calling _process_endpoint_event')
processed, alert = asyncio.run(_process_endpoint_event(LogEvent(**BASE_EVENT), ctx))
print('processed', processed)
print('alert', alert)
resp = client.post('/api/v1/endpoints/log_batch', json={'events':[BASE_EVENT], 'send_alerts': True, 'include_rules': True, 'classify': True})
print('post status', resp.status_code)
print('after ring len', len(_ALERT_RING))
with _ALERT_RING_LOCK:
    print('ring contents', list(_ALERT_RING))
