from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)
headers = {'x-api-key': 'devkey123'}

# 1) Check graph session build
r = client.post('/api/v1/graph/session/build', headers=headers, json={'session_ids': ['batch-1','batch-2'], 'correlate': True})
print('graph build status', r.status_code)
try:
    print('graph build json:', r.json())
except Exception:
    print('graph build text:', r.text)

# 2) Check static page
r2 = client.get('/static/csv_multi_analyzer.html')
print('static page status', r2.status_code)
print('static page length', len(r2.text or ''))
