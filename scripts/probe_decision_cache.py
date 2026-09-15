from fastapi.testclient import TestClient
from src.api.server import app, DECISION_CACHE

client = TestClient(app)

event_id = 'probe-e2e-1'
payload = {
    'id': event_id,
    'event_type': 'process_start',
    'details': {'process': {'name': 'rundll32.exe', 'parent_name': 'wscript.exe'}}
}

r = client.post('/api/v1/events', json=payload)
print('status', r.status_code)
print('DECISION_CACHE has key?', event_id in DECISION_CACHE)
val = DECISION_CACHE.get(event_id)
print('type:', type(val))
print('repr:', repr(val))
try:
    print('factors attr:', getattr(val, 'factors', None))
except Exception as e:
    print('factors access error', e)

# show module-level refs ids
import sys
for mod_name in ('src.api.server', 'api.server', 'src.api.runtime_state', 'api.runtime_state'):
    m = sys.modules.get(mod_name)
    print(mod_name, 'loaded?', bool(m), 'DECISION_CACHE id:', id(getattr(m, 'DECISION_CACHE', None)) if m else None)
print('canonical DECISION_CACHE id:', id(DECISION_CACHE))
