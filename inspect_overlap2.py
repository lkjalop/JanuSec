import os, json
from fastapi.testclient import TestClient
from src.api.app import app
client = TestClient(app)
payload = {"session_ids": ["batch-overlap-alpha","batch-overlap-beta"], "correlate": True, "ewma": False}
r = client.post('/api/v1/graph/session/build', json=payload, headers={'x-api-key':'devkey123'})
summary = r.json()['summary']
sid = r.json()['session_id']
print('Session IDs in summary:', summary.get('session_ids'))
print('Correlation:', summary.get('correlation'))
print('Confidence breakdown:', summary.get('confidence_breakdown'))
# Now get session summary via endpoint
sr = client.get(f'/api/v1/graph/session/{sid}', headers={'x-api-key':'devkey123'})
print('GET /session status', sr.status_code)
print('Stored correlation:', sr.json()['summary'].get('correlation'))
# Explain
er = client.get(f'/api/v1/graph/session/{sid}/explain', headers={'x-api-key':'devkey123'})
print('Explain status', er.status_code)
print('Explain payload:', er.json() if er.status_code==200 else er.text)
