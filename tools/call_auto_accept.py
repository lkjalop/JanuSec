from fastapi.testclient import TestClient
from src.api.server import app
import os, json
os.environ['API_KEYS_JSON'] = json.dumps([{'key': 'k3', 'scopes': ['factors.search', 'recalibrator.admin']}])
client = TestClient(app)
resp = client.post('/api/v1/risk/calibration/auto_accept', headers={'x-api-key':'k3'})
print('status', resp.status_code)
try:
    print(resp.json())
except Exception:
    print(resp.text)
