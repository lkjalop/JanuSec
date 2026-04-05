from fastapi.testclient import TestClient


def test_explain_mapping_tags_for_intune():
    # Insert a decision with an Intune factor and verify explain returns mapping_tags.mitre
    from src.api.server import app
    from src.api import runtime_state
    client = TestClient(app)

    event_id = 'evt-intune-mapping-1'
    dec = {
        'event_id': event_id,
        'id': event_id,
        'verdict': 'SUSPICIOUS',
        'confidence': 0.6,
        'factors': ['iam:intune_compliance_policy_disabled'],
    }
    runtime_state.cache_set(event_id, dec)

    r = client.get(f'/api/v1/decisions/{event_id}/explain')
    assert r.status_code == 200, r.text
    body = r.json()
    tags = body.get('mapping_tags') or {}
    assert 'mitre' in tags
    # T1562 = Impair Defenses
    assert 'T1562' in tags['mitre']

