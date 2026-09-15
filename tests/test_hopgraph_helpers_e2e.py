import os
from fastapi.testclient import TestClient


def test_hopgraph_helper_node_after_identity_ingest():
    # Enable helpers and IAM detectors
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    os.environ['ENABLE_IAM_FACTORS'] = '1'

    from src.api.app import app as api_app
    client = TestClient(api_app)

    # Ingest identity event that should trigger AS-REP roasting factor
    payload = {
        'user': 'alice@example.com',
        'event_type': 'AS-REP request'
    }
    r = client.post('/api/v1/identity/ingest', json=payload)
    assert r.status_code == 200, r.text

    # Query helper endpoint for node details
    node_id = 'user:alice@example.com'
    r2 = client.get(f'/api/v1/test/hopgraph/node/{node_id}')
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body.get('status') in {'ok','mock'}
    if body.get('status') == 'ok':
        factors = set(body.get('factors') or [])
        assert 'iam:as_rep_roasting' in factors

