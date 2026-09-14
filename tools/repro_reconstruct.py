import os
os.environ.setdefault('PYTEST_CURRENT_TEST','1')
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)
resp = client.post('/api/v1/graph/reconstruct', json={'user': 'u1'})
print('status', resp.status_code)
try:
    print('json', resp.json())
except Exception:
    print('text', resp.text)
print('headers sent by client:')
# testclient uses default headers; show request content for server logs via test server?
