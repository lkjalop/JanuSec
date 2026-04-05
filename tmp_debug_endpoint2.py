from fastapi.testclient import TestClient
from src.api.server import app
from src.api import runtime_state
client = TestClient(app)
payload = {
    'id': 'debug-e2e2',
    'event_type': 'process_start',
    'details': {'process': {'name': 'rundll32.exe','parent_name': 'wscript.exe'}}
}
resp = client.post('/api/v1/events', json=payload)
print('status', resp.status_code, resp.text)
print('cache keys', list(runtime_state.DECISION_CACHE.keys()))
print('value', runtime_state.cache_get('debug-e2e2'))
