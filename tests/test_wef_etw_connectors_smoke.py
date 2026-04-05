import os
import time
import json
import pytest
from src.api.app import app


@pytest.fixture(scope='module')
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from fastapi.testclient import TestClient
    return TestClient(app)


API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')

def _h():
    return { 'x-api-key': API_KEY, 'Content-Type': 'application/json' }


def test_wef_etw_ingest_smoke(client):
    """Smoke test: POST a small WEF/ETW-like payload to the connectors ingest endpoint.
    The test mirrors the existing sysmon/suricata smoke tests: it ensures the route
    exists and returns 200/ok for a minimal well-formed payload.
    """
    payload = {
        "source": "wef",
        "events": [
            {"ts": int(time.time()), "event_id": "wef-test-1", "event_type": "Logon", "host": "test-host", "user": "TEST\\alice", "details": {"status": "success"}}
        ]
    }
    # use the platform's WEF/ETW ingest endpoints like other connector smoke tests
    r1 = client.post('/api/v1/ingest/wef', headers=_h(), data=json.dumps(payload))
    assert r1.status_code in (200,201), r1.text
    j1 = r1.json(); assert (('accepted' in j1 and j1['accepted'] >= 1) or ('ingested' in j1 and j1['ingested'] >= 1))

    # also exercise the ETW ingest path
    r2 = client.post('/api/v1/ingest/etw', headers=_h(), data=json.dumps(payload))
    assert r2.status_code in (200,201), r2.text
    j2 = r2.json(); assert (('accepted' in j2 and j2['accepted'] >= 1) or ('ingested' in j2 and j2['ingested'] >= 1))