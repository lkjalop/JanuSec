from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})
from src.config import risk_loader

client = TestClient(app)

def test_weight_history_records_after_votes():
    # Vote twice on a factor to create history
    for label in ['true_positive','false_positive']:
        r = client.post('/api/v1/feedback/decision', json={
            'decision_id': f'hist-{label}',
            'label': label,
            'factors': ['lateral'],
            'apply_calibration': True
        }, headers={'x-api-key': 'devkey123'})
        assert r.status_code == 200, r.text
    rh = client.get('/api/v1/factors/history/lateral')
    assert rh.status_code == 200, rh.text
    data = rh.json()
    assert data['factor'] == 'lateral'
    assert isinstance(data['history'], list)
    assert len(data['history']) >= 2
