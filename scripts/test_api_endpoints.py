from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)

def pretty(resp):
    try:
        return resp.json()
    except Exception:
        return resp.text

print('GET /api/v1/correlation/top_pairs')
r = client.get('/api/v1/correlation/top_pairs')
print(r.status_code)
print(pretty(r))

print('\nGET /api/v1/correlation/persisted')
r = client.get('/api/v1/correlation/persisted')
print(r.status_code)
print(pretty(r))

print('\nGET /api/v1/graph/explain?node=test-node')
r = client.get('/api/v1/graph/explain', params={'node': 'test-node'})
print(r.status_code)
print(pretty(r))
