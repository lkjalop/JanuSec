import time
from fastapi.testclient import TestClient
from src.api.server import app
from src.api import runtime_state
client = TestClient(app)
payload = {
    'id': 'debug-e2e',
    'event_type': 'process_start',
    'details': {
        'process': {
            'name': 'rundll32.exe',
            'parent_name': 'wscript.exe'
        }
    }
}
resp = client.post('/api/v1/events', json=payload)
print('status', resp.status_code, resp.text)
for _ in range(40):
    rec = runtime_state.cache_get('debug-e2e')
    if rec is not None:
        print('found', rec)
        break
    time.sleep(0.05)
else:
    print('not found')
