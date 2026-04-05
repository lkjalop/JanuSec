import os, json
from fastapi.testclient import TestClient
from src.api.app import app
client = TestClient(app)
payload = {"session_ids": ["batch-overlap-alpha","batch-overlap-beta"], "correlate": True, "ewma": False}
r = client.post('/api/v1/graph/session/build', json=payload, headers={'x-api-key':'devkey123'})
print('Status build', r.status_code)
print('Correlation:', r.json()['summary'].get('correlation'))
print('Edges:', r.json()['summary'].get('graph_summary',{}).get('edges'))
sid = r.json()['session_id']
er = client.get(f'/api/v1/graph/session/{sid}/explain', headers={'x-api-key':'devkey123'})
print('Explain status', er.status_code)
if er.status_code==200:
    print('Hotspots:', er.json().get('overlap_hotspots'))
else:
    print('Explain error', er.text)
