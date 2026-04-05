from fastapi.testclient import TestClient
import os

from src.api.server import app

client = TestClient(app)

# Prepare environment similar to test
os.environ['API_KEYS_JSON'] = '[{"key":"k3","scopes":["factors.search"]}]'
try:
    import jwt
    os.environ['JWT_SECRET'] = 'test-jwt-secret'
    token = jwt.encode({'sub':'t','scopes':['factors.search']}, os.environ['JWT_SECRET'], algorithm='HS256')
    auth_hdr = {'Authorization': f'Bearer {token}'}
except Exception:
    auth_hdr = {'x-api-key': 'k3'}

resp = client.post('/api/v1/risk/calibration/auto_accept', headers=auth_hdr)
print('status', resp.status_code)
print('json', resp.text)
