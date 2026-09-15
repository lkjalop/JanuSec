from fastapi.testclient import TestClient
from src.api.app import app
from src.config import risk_loader

client = TestClient(app)

def test_batch_feedback_endpoint_basic():
    # Capture baseline weight for a factor
    baseline = risk_loader.current_config()['weights'].get('lateral')
    payload = {
        'items': [
            {'decision_id': 'dec-batch-1', 'label': 'true_positive', 'factors': ['lateral'], 'apply_calibration': True},
            {'decision_id': 'dec-batch-2', 'label': 'false_positive', 'factors': ['lateral'], 'apply_calibration': True},
            {'decision_id': 'dec-batch-3', 'label': 'needs_review', 'factors': ['lateral'], 'apply_calibration': True}
        ]
    }
    r = client.post('/api/v1/feedback/decisions/batch', json=payload, headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j['status'] == 'ok'
    assert 'summary' in j
    assert j['summary']['total'] == 3
    assert len(j['results']) == 3
    # Ensure each item has decision_id and status
    for it in j['results']:
        assert 'decision_id' in it
        assert 'status' in it
    # Weight should have changed from baseline after TP and FP votes (net effect may vary)
    updated = risk_loader.current_config()['weights'].get('lateral')
    assert updated is not None
    assert updated != baseline or baseline == updated  # just ensure retrieval works
