import os,json
# ensure API key env before app import
os.environ['API_KEYS_JSON'] = json.dumps([{'key':'testkey','scopes':['feedback.write','factors.search','risk.read']}])
from fastapi.testclient import TestClient
from src.api.server import app
client = TestClient(app)
resp = client.get('/api/v1/risk/calibration/export', headers={'x-api-key':'testkey'})
print('status', resp.status_code)
try:
    print('json:', resp.json())
except Exception:
    print('text:', resp.text)
print('headers:', resp.headers)
