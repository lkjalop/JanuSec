from fastapi.testclient import TestClient

from src.api.server import app
from src.api import runtime_state

client = TestClient(app)


def test_mitre_prefix_counted_in_report_top_mitre():
    class Dummy: pass
    d = Dummy()
    d.event_id = 'evt-mitre-meta-1'
    d.verdict = 'malicious'
    d.confidence = 0.92
    d.factors = ['mitre:T1059', 'net:beacon_periodic']
    d.tenant_id = 'public'
    runtime_state.cache_set(d.event_id, d)

    r = client.get('/api/v1/report/ingestion?include_alerts=false&format=json')
    assert r.status_code == 200
    body = r.json()
    techs = {t['technique'] for t in body.get('top_mitre_techniques', [])}
    assert 'T1059' in techs
