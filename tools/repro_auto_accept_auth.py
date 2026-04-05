import os
os.environ.setdefault('PYTEST_CURRENT_TEST','1')
from src.api.app import app
from fastapi.testclient import TestClient
import json
client = TestClient(app)
# Build auth header via pyjwt if available
try:
    import jwt
    os.environ['JWT_SECRET'] = 'test-jwt-secret'
    token = jwt.encode({'sub': 't', 'scopes': ['factors.search']}, os.environ['JWT_SECRET'], algorithm='HS256')
    headers = {'Authorization': f'Bearer {token}'}
except Exception:
    headers = {'x-api-key': 'k3'}
resp = client.post('/api/v1/risk/calibration/auto_accept', headers=headers)
print('STATUS', resp.status_code)
try:
    print('JSON', json.dumps(resp.json(), indent=2))
except Exception:
    print('TEXT', resp.text)
