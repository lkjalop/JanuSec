import os

from fastapi.testclient import TestClient

from src.api.server import app

client = TestClient(app)

def test_stream_pcap_accepts_and_queues(tmp_path, monkeypatch):
    # Ensure enqueue is available and is a no-op for tests
    class DummyQ:
        def enqueue(self, job):
            async def _c():
                return True
            return _c()
    monkeypatch.setenv('INGEST_API_KEY', 'testkey')
    monkeypatch.setenv('DEFAULT_TENANT', 'public')
    # inject dummy EVENT_QUEUE into server module
    import src.api.runtime_state as rs
    rs.EVENT_QUEUE = DummyQ()

    from tests._helpers import default_test_headers
    headers = default_test_headers('10.1.2.3')
    # ensure ingest API key matches monkeypatched env
    headers.update({'X-API-Key': 'testkey', 'X-Tenant-Id': 'unit'})
    data = b'\xd4\xc3\xb2\xa1' + b'0' * 1024  # minimal pcap magic + payload
    r = client.post('/api/v1/ingest/stream-pcap', headers=headers, data=data)
    assert r.status_code == 200
    body = r.json()
    assert body.get('status') == 'accepted'
    assert 'session_id' in body