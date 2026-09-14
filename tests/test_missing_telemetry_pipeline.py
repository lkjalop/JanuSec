import os
import time
from fastapi.testclient import TestClient

os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('FAST_TEST_MODE','1')
os.environ.setdefault('DISABLE_DB','1')

from src.api.app import app

client = TestClient(app)

def test_enqueue_and_list_telemetry_request():
    payload = {
        'domain': 'identity',
        'entity': 'Alice@Example',
        'window': '24h',
        'connector': 'purview',
    }
    r = client.post('/api/v1/telemetry_requests', json=payload)
    assert r.status_code == 200
    jid = r.json().get('id')
    assert isinstance(jid, str)

    # Inline processing should mark as done in FAST_TEST_MODE
    time.sleep(0.05)
    r2 = client.get('/api/v1/telemetry_requests?limit=10')
    assert r2.status_code == 200
    data = r2.json()
    items = data.get('items') or []
    assert any(it.get('id') == jid and it.get('status') in {'done','error'} for it in items)
