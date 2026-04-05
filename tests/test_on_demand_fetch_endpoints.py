import json
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)

def test_fetch_lines_zeek_generic():
    payload = {
        "source": "zeek",
        "kind": "dns",
        "lines": [json.dumps({"query":"example.com","uid":"X"})],
        "filters": {"user":"alice","host":"h1"},
        "limit": 10
    }
    r = client.post('/api/v1/fetch/lines', json=payload, headers={'x-api-key':'devkey123'})
    assert r.status_code == 200
    j = r.json()
    assert 'session_id' in j and 'session' in j
    assert isinstance(j['session']['data']['events'], list)


def test_fetch_zeek_synthetic():
    payload = {
        "source": "zeek",
        "filters": {"user":"alice","host":"h1"},
        "time_window": {"last":"-10m"},
        "limit": 5
    }
    r = client.post('/api/v1/fetch/zeek', json=payload, headers={'x-api-key':'devkey123'})
    assert r.status_code == 200
    j = r.json()
    assert 'session_id' in j and 'session' in j
    evs = j['session']['data']['events']
    assert isinstance(evs, list)
    assert len(evs) >= 3


def test_capture_stubs():
    r = client.post('/api/v1/capture/pcap/start', json={"reason":"test","duration_seconds":60}, headers={'x-api-key':'devkey123'})
    assert r.status_code == 200
    j = r.json()
    assert j['status'] == 'pending_approval'
    r2 = client.post('/api/v1/capture/ebpf/start', json={"reason":"test","profile":"net+proc-min"}, headers={'x-api-key':'devkey123'})
    assert r2.status_code == 200
