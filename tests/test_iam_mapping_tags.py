from fastapi.testclient import TestClient


def test_explain_mapping_tags_for_iam():
    # Insert a decision with an IAM factor and verify explain returns mapping_tags.mitre
    from src.api.server import app
    from src.api import runtime_state
    client = TestClient(app)

    event_id = 'evt-iam-mapping-1'
    dec = {
        'event_id': event_id,
        'id': event_id,
        'verdict': 'SUSPICIOUS',
        'confidence': 0.6,
        'factors': ['iam:as_rep_roasting'],
    }
    runtime_state.cache_set(event_id, dec)

    r = client.get(f'/api/v1/decisions/{event_id}/explain')
    assert r.status_code == 200, r.text
    body = r.json()
    tags = body.get('mapping_tags') or {}
    assert 'mitre' in tags
    assert 'T1558.004' in tags['mitre']


def test_report_includes_iam_mitre():
    # Ensure report aggregates IAM factors into top_mitre_techniques
    from src.api.server import app
    from src.api import runtime_state
    client = TestClient(app)

    class Dummy: pass
    d = Dummy()
    d.event_id = 'evt-iam-mapping-2'
    d.verdict = 'malicious'
    d.confidence = 0.9
    # Report aggregation should include mapping-derived MITRE for IAM-only factors
    # without requiring explicit 'mitre:' tokens.
    d.factors = ['iam:as_rep_roasting']
    d.tenant_id = 'public'
    runtime_state.cache_set(d.event_id, d)

    r = client.get('/api/v1/report/ingestion?include_alerts=false&format=json')
    assert r.status_code == 200, r.text
    top = r.json().get('top_mitre_techniques') or []
    techs = {t.get('technique') for t in top if isinstance(t, dict)}
    assert 'T1558.004' in techs
