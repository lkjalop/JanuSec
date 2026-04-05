import json

from fastapi.testclient import TestClient

from src.api.server import app

client = TestClient(app)

def test_integrations_status():
    r = client.get('/api/v1/integrations/status')
    assert r.status_code == 200
    data = r.json()
    for key in ['slack','teams','xdr']:
        assert key in data
        assert 'connected' in data[key]

def test_toggle_integration():
    r = client.post('/api/v1/integrations/slack/toggle?enabled=true')
    assert r.status_code == 200
    assert r.json()['connected'] is True


def test_dashboard_status():
    r = client.get('/api/v1/status/dashboard')
    assert r.status_code == 200
    d = r.json()
    assert 'alerts' in d and 'critical' in d['alerts']


def test_dashboard_metrics():
    r = client.get('/api/v1/dashboard/metrics')
    assert r.status_code == 200
    d = r.json()
    for k in ['critical_threats','artifacts_analyzed','detection_rate','avg_response_time','timestamp']:
        assert k in d


def test_alerts_recent_shape():
    r = client.get('/api/v1/alerts/recent')
    assert r.status_code == 200
    d = r.json()
    assert 'alerts' in d
    if d['alerts']:
        a = d['alerts'][0]
        for k in ['id','title','mitre','severity','age']:
            assert k in a


def test_upload_endpoint_schema(monkeypatch):
    # Simulate small text file upload
    files = [
        ('files', ('a.log', b'line1\nline2 error\n', 'text/plain')),
        ('files', ('b.json', b'[{"a":1},{"b":2}]', 'application/json')),
    ]
    r = client.post('/api/v1/upload/files', files=files)
    assert r.status_code == 200
    d = r.json()
    for k in ['files_processed','total_threats_detected','results']:
        assert k in d
