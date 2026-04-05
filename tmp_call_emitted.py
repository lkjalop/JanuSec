from fastapi.testclient import TestClient
from src.api.app import app
client=TestClient(app)
resp=client.get('/api/v1/factors/emitted')
print(resp.status_code)
print(resp.text)
