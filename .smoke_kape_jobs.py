from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)
resp = client.get('/api/v1/kape/jobs', headers={'x-api-key':'devkey123'})
print('status', resp.status_code)
print(resp.json())
