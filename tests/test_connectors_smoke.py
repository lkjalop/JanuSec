import os
import json
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
    return { 'x-api-key': API_KEY, 'Content-Type': 'application/json' }


def test_sysmon_wef_smoke(client):
    payload = {
        "events": [
            { "EventID": "1", "SourceIp": "10.1.1.5", "DestinationIp": "10.1.1.6", "User": "svc_user", "Computer": "host-01", "Image": "C:\\Windows\\System32\\notepad.exe", "sha256": "deadbeef" }
        ]
    }
    r = client.post('/api/v1/ingest/sysmon', headers=_h(), data=json.dumps(payload))
    assert r.status_code in (200,201)
    j = r.json(); assert (('accepted' in j and j['accepted'] >= 1) or ('ingested' in j and j['ingested'] >= 1))


def test_suricata_smoke(client):
    payload = { "events": [ { "src_ip": "192.168.0.5", "dest_ip": "1.2.3.4", "event_type": "alert", "app_proto": "http" } ] }
    r = client.post('/api/v1/ingest/suricata', headers=_h(), data=json.dumps(payload))
    assert r.status_code in (200,201)
    j = r.json(); assert (('accepted' in j and j['accepted'] >= 1) or ('ingested' in j and j['ingested'] >= 1))


def test_crowdstrike_smoke(client):
    payload = { "detections": [ { "LocalIP": "10.0.0.7", "RemoteIP": "10.0.0.9", "UserName": "charlie", "ComputerName": "work-03", "FileName": "malware.exe", "SHA256HashData": "cafebabe" } ] }
    r = client.post('/api/v1/ingest/endpoint', headers=_h(), data=json.dumps(payload))
    assert r.status_code in (200,201)
    j = r.json(); assert (('accepted' in j and j['accepted'] >= 1) or ('ingested' in j and j['ingested'] >= 1))


def test_cloudtrail_smoke(client):
    payload = { "Records": [ { "eventVersion": "1.08", "eventTime": "2025-12-16T12:00:00Z", "eventSource": "ec2.amazonaws.com", "eventName": "StartInstances", "awsRegion": "us-east-1", "sourceIPAddress": "3.3.3.3", "userIdentity": { "userName": "awsuser" } } ] }
    r = client.post('/api/v1/ingest/cloudtrail', headers=_h(), data=json.dumps(payload))
    assert r.status_code in (200,201)
    j = r.json(); assert (('accepted' in j and j['accepted'] >= 1) or ('ingested' in j and j['ingested'] >= 1))


def test_wef_smoke(client):
    payload = {
        "events": [
            { "EventID": "4688", "Computer": "wef-host-01", "SubjectUserName": "CORP\\alice", "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "IpAddress": "10.10.10.5", "DestinationIp": "10.10.10.8" }
        ]
    }
    r = client.post('/api/v1/ingest/wef', headers=_h(), data=json.dumps(payload))
    assert r.status_code in (200,201)
    j = r.json(); assert (('accepted' in j and j['accepted'] >= 1) or ('ingested' in j and j['ingested'] >= 1))


def test_etw_smoke(client):
    payload = {
        "events": [
            { "EventId": "1", "ComputerName": "etw-host-02", "TargetUserName": "svc_etw", "ProcessName": "powershell.exe", "SourceAddress": "192.0.2.10", "DestinationAddress": "192.0.2.20", "Hashes": "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
        ]
    }
    r = client.post('/api/v1/ingest/etw', headers=_h(), data=json.dumps(payload))
    assert r.status_code in (200,201)
    j = r.json(); assert (('accepted' in j and j['accepted'] >= 1) or ('ingested' in j and j['ingested'] >= 1))
