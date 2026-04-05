from fastapi.testclient import TestClient
from src.api.app import app


def test_persona_view_contains_enrichment_and_dread():
    client = TestClient(app)
    # inline demo payload with minimal artifact and auth
    payload = {
        'report_id': 'r-demo',
        'artifact': {'destination_ports': [22], 'destination_ips': ['10.0.0.1'], 'business_tier': 'high'},
        'verdict': {'all_factors': [{'name': 'vulnerability_matches', 'value': [{'cvss': 9.0, 'exploit_available': True}]}], 'auth': {'dkim': 'pass', 'spf': 'pass'}},
        'raw_event': {'headers': {'From': 'alice@example.com'}, 'auth': {'dkim': 'pass', 'spf': 'pass'}, 'envelope': {'return_path': 'bounce@example.com'}}
    }
    r = client.post('/api/v1/reports/persona_view?top_n=3', json=payload)
    assert r.status_code == 200
    j = r.json()
    ss = j.get('summary_signals') or {}
    assert 'enrichment' in ss
    assert 'dread' in ss
