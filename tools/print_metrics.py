from fastapi.testclient import TestClient
from src.api.app import app
import json

c = TestClient(app)
r = c.get('/api/v1/metrics/summary')
print('STATUS', r.status_code)
print(json.dumps(r.json(), indent=2))
