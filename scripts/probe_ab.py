import sys
sys.path.insert(0, r'D:\AI\Threat_thy_sniffer')
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)
API_HEADERS = {'x-api-key': 'devkey123'}
now = datetime.utcnow()
payloads = [
    {"test_id": 't42', "tenant_id": 't1', "variant": "A", "tp": 80, "fp": 20, "fn": 10, "started_at": (now - timedelta(days=2)).isoformat(), "ended_at": (now - timedelta(days=1)).isoformat()},
    {"test_id": 't42', "tenant_id": 't1', "variant": "B", "tp": 70, "fp": 30, "fn": 15, "started_at": (now - timedelta(days=2)).isoformat(), "ended_at": (now - timedelta(days=1)).isoformat()},
]
for p in payloads:
    r = client.post('/api/v1/metrics/ab_test/result', json=p, headers=API_HEADERS)
    print('status:', r.status_code)
    print('body:', r.text)
