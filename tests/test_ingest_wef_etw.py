import os
import pytest


API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')


@pytest.fixture(scope='module')
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from src.api.app import app
    from fastapi.testclient import TestClient
    return TestClient(app)


def _h():
    return {'x-api-key': API_KEY, 'Content-Type': 'application/json'}


def test_wef_ingest_and_query(client):
    payload = {
        "events": [
            {
                "EventID": "4688",
                "Computer": "wef-host-01",
                "SubjectUserName": "CORP\\alice",
                "NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
                "IpAddress": "10.10.10.5",
                "DestinationIp": "10.10.10.8"
            }
        ]
    }
    r = client.post('/api/v1/ingest/wef', headers=_h(), json=payload)
    assert r.status_code in (200, 201)
    j = r.json()
    assert (('accepted' in j and j['accepted'] >= 1) or ('ingested' in j and j['ingested'] >= 1))

    q = client.post('/api/v1/ingest/events/query', json={'user': 'CORP\\alice'})
    assert q.status_code == 200
    detail = q.json().get('detail') or {}
    timeline = detail.get('timeline') or []
    assert any(ev.get('sensor') == 'wef' for ev in timeline)


def test_etw_ingest_and_query(client):
    payload = {
        "events": [
            {
                "EventId": "1",
                "ComputerName": "etw-host-02",
                "TargetUserName": "svc_etw",
                "ProcessName": "powershell.exe",
                "SourceAddress": "192.0.2.10",
                "DestinationAddress": "192.0.2.20",
                "Hashes": "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        ]
    }
    r = client.post('/api/v1/ingest/etw', headers=_h(), json=payload)
    assert r.status_code in (200, 201)
    j = r.json()
    assert (('accepted' in j and j['accepted'] >= 1) or ('ingested' in j and j['ingested'] >= 1))

    q = client.post('/api/v1/ingest/events/query', json={'host': 'etw-host-02'})
    assert q.status_code == 200
    detail = q.json().get('detail') or {}
    timeline = detail.get('timeline') or []
    assert any(ev.get('sensor') == 'etw' for ev in timeline)
