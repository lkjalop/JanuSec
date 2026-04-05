from fastapi.testclient import TestClient
from src.api.app import app
API_HEADERS = {'x-api-key': 'devkey123'}
client = TestClient(app)
# seed via helper
payloads = [
    {"test_id": "t42", "tenant_id": "t1", "variant": "A", "tp": 80, "fp": 20, "fn": 10, "started_at": '2026-01-01T00:00:00'},
    {"test_id": "t42", "tenant_id": "t1", "variant": "B", "tp": 70, "fp": 30, "fn": 15, "started_at": '2026-01-01T00:00:00'},
]
for p in payloads:
    r = client.post('/api/v1/metrics/ab_test/result', json=p, headers=API_HEADERS)
    print('POST', r.status_code, r.text)
# call analysis
o = client.get('/openapi.json')
print('/api/v1/metrics/ab/analysis in openapi:', '/api/v1/metrics/ab/analysis' in o.json().get('paths', {}))
r = client.get('/api/v1/metrics/ab/analysis', params={'tenant_id':'t1','test_id':'t42'}, headers=API_HEADERS)
print('ANALYSIS', r.status_code, r.text)
