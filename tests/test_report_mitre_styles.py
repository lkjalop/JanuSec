from fastapi.testclient import TestClient

from src.api.server import app
from src.api import runtime_state

client = TestClient(app)


def test_legacy_and_direct_mitre_styles_in_top_list():
    class Dummy: pass

    d1 = Dummy(); d1.event_id='evt-mitre-legacy-1'; d1.verdict='malicious'; d1.confidence=0.95; d1.factors=['mitre_TA0008']; d1.tenant_id='public'
    d2 = Dummy(); d2.event_id='evt-mitre-direct-1'; d2.verdict='review'; d2.confidence=0.8; d2.factors=['T1566.001']; d2.tenant_id='public'

    runtime_state.cache_set(d1.event_id, d1)
    runtime_state.cache_set(d2.event_id, d2)

    r = client.get('/api/v1/report/ingestion?include_alerts=false&format=json')
    assert r.status_code == 200
    data = r.json()
    techs = {t['technique'] for t in data.get('top_mitre_techniques', [])}
    assert 'TA0008' in techs
    assert 'T1566.001' in techs
