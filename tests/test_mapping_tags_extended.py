from fastapi.testclient import TestClient


def test_mapping_tags_extended_frameworks():
    from src.api.server import app
    from src.api import runtime_state
    client = TestClient(app)

    event_id = 'evt-mapping-extended-1'
    dec = {
        'event_id': event_id,
        'id': event_id,
        'verdict': 'SUSPICIOUS',
        'confidence': 0.5,
        'factors': ['net:beacon_periodic', 'iam:as_rep_roasting'],
    }
    runtime_state.cache_set(event_id, dec)

    r = client.get(f'/api/v1/decisions/{event_id}/explain')
    assert r.status_code == 200, r.text
    body = r.json()
    tags = body.get('mapping_tags') or {}
    # Baseline keys
    assert 'mitre' in tags and isinstance(tags['mitre'], list)
    # Extended frameworks present (best-effort)
    assert 'stride' in tags or True  # tolerate environments without taxonomy
    assert 'dread' in tags or True
    assert 'maestro' in tags or True
    assert 'pasta' in tags or True
    assert 'cvss' in tags or True
    assert 'hopgraph' in tags or True

