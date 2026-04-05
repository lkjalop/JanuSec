import os, json
os.environ['PYTEST_CURRENT_TEST'] = '1'
os.environ['API_KEYS_JSON'] = json.dumps([{'key': 'k3', 'scopes': ['factors.search', 'recalibrator.admin']}])
# ensure test helper env flags
os.environ['TEST_HELPERS_ENABLED'] = '1'
from fastapi.testclient import TestClient
from src.api.server import app
client = TestClient(app)
resp = client.post('/api/v1/risk/calibration/auto_accept', headers={'x-api-key':'k3'})
print('status', resp.status_code)
print(resp.text)
