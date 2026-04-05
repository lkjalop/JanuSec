from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)
now = datetime.utcnow()
payload = {
    "test_id": "t42",
    "tenant_id": "t1",
    "variant": "A",
    "tp": 80,
    "fp": 20,
    "fn": 10,
    "started_at": (now - timedelta(days=2)).isoformat(),
    "ended_at": (now - timedelta(days=1)).isoformat(),
}
resp = client.post('/api/v1/metrics/ab_test/result', json=payload, headers={'x-api-key':'devkey123'})
print('status:', resp.status_code)
print('body:', resp.text)
