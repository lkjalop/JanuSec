from fastapi.testclient import TestClient
from src.api.app import app


def test_compute_dread_endpoint():
    client = TestClient(app)
    artifact = {'destination_ports': [22], 'destination_ips': ['10.0.0.1'], 'business_tier': 'critical'}
    factors = [{'name': 'vulnerability_matches', 'value': [{'cvss': 9.0, 'exploit_available': True}]}]
    r = client.post('/api/v1/enrichment/dread/score', json={'artifact': artifact, 'factors': factors})
    assert r.status_code == 200
    j = r.json()
    assert 'breakdown' in j
    assert 'composite' in j['breakdown']
    assert j['breakdown']['composite'] >= 0


def test_bulk_triage_endpoint():
    client = TestClient(app)
    rows = [{'report_id': 'r1', 'action': 'quarantine_for_review'}, {'report_id': 'r2', 'action': 'mark_pending'}]
    headers = {'x-api-key': 'devkey123'}
    r = client.post('/api/v1/reports/bulk_triage', json={'rows': rows}, headers=headers)
    assert r.status_code == 200
    j = r.json()
    assert j.get('ok') is True
    assert 'applied' in j
