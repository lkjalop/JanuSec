from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from src.api.app import app
import json

API_HEADERS = {'x-api-key': 'devkey123'}

client = TestClient(app)
start_day = (datetime.utcnow() - timedelta(days=3)).date()
rows = [
    {"day": start_day, "tp": 10, "fp": 5, "fn": 2},
    {"day": start_day + timedelta(days=1), "tp": 8, "fp": 8, "fn": 3},
    {"day": start_day + timedelta(days=2), "tp": 12, "fp": 6, "fn": 4},
]
for r in rows:
    payload = {"day": r["day"].isoformat(), "tenant_id": 't1', "tp": r["tp"], "fp": r["fp"], "fn": r["fn"]}
    resp = client.post('/api/v1/metrics/precision/daily', json=payload, headers=API_HEADERS)
    print('POST', payload, '->', resp.status_code, resp.json())

resp = client.get('/api/v1/metrics/precision/daily', params={'tenant_id':'t1','start': start_day.isoformat(),'end': (start_day + timedelta(days=3)).isoformat()}, headers=API_HEADERS)
print('GET status', resp.status_code)
print(json.dumps(resp.json(), indent=2))
