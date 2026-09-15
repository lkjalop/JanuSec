import os
import json
import pytest

# Many routes require x-api-key; default dev key
API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')

@pytest.fixture(scope="module")
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')  # avoid DB in unit tests
    from src.api.app import create_app
    app = create_app({'mode': 'test'})
    try:
        from fastapi.testclient import TestClient
    except Exception:
        pytest.skip("FastAPI TestClient not available")
    return TestClient(app)


def _headers():
    return { 'x-api-key': API_KEY, 'Content-Type': 'application/json' }


def test_ingest_splunk_basic(client):
    payload = {
        "source": "splunk",
        "events": [
            {
                "source.ip": "10.0.0.5",
                "destination.ip": "10.0.0.8",
                "user.name": "alice",
                "host.name": "workstation-01",
                "process.name": "powershell.exe",
                "file.hash.sha256": "abc123",
                "url.domain": "example.com",
                "event.action": "network_connection"
            }
        ]
    }
    r = client.post('/api/v1/ingest/splunk', headers=_headers(), data=json.dumps(payload))
    assert r.status_code in (200, 201)
    data = r.json()
    assert 'accepted' in data and data['accepted'] >= 1


def test_ingest_elastic_basic(client):
    payload = {
        "source": "elastic",
        "events": [
            {
                "source.ip": "172.16.1.7",
                "destination.ip": "8.8.8.8",
                "user.name": "bob",
                "host.name": "srv-02",
                "process.name": "curl",
                "file.hash.sha256": "def456",
                "url.domain": "google.com",
                "event.action": "dns_query"
            }
        ]
    }
    r = client.post('/api/v1/ingest/elastic', headers=_headers(), data=json.dumps(payload))
    assert r.status_code in (200, 201)
    data = r.json()
    assert 'accepted' in data and data['accepted'] >= 1
