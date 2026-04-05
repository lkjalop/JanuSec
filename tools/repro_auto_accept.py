from src.api.app import app
from fastapi.testclient import TestClient
import os, json
os.environ.setdefault('PYTEST_CURRENT_TEST','1')
client = TestClient(app)
resp = client.post('/api/v1/risk/calibration/auto_accept')
print('STATUS', resp.status_code)
try:
    print('JSON:', json.dumps(resp.json(), indent=2))
except Exception:
    print('TEXT:', resp.text)
