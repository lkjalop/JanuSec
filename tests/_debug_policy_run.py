from fastapi.testclient import TestClient
import time
from src.api.server import app

client = TestClient(app)

from src.api.runtime_state import cache_set as _cache_set

event_id = f'debug-event-{int(time.time()*1000)}'
entry = {
    'event_id': event_id,
    'verdict': 'GOOD',
    'confidence': 0.12,
    'factors': ['unit:test'],
    'risk_score': 0.12,
    'risk_breakdown': [{'factor': 'unit:test', 'contribution': 0.12}],
}
_cache_set(event_id, entry)

api_key = 'testkey-phase1'
headers = {'x-api-key': api_key}
print('POST /api/v1/csv/policy ->', client.post('/api/v1/csv/policy', headers=headers, json={'never_auto_clear': True}).status_code)

print('\nGET /api/v1/decisions/{id}/explain')
r = client.get(f'/api/v1/decisions/{event_id}/explain', headers=headers)
print(r.status_code)
print(r.text)

print('\nGET /api/v1/decisions/{id}/risk')
r2 = client.get(f'/api/v1/decisions/{event_id}/risk', headers=headers)
print(r2.status_code)
print(r2.text)
