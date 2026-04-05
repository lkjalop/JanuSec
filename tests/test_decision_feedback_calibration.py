from fastapi.testclient import TestClient
from src.api.app import app
from src.config import risk_loader

client = TestClient(app)

def test_decision_feedback_calibration_increases_weight(tmp_path):
    cfg = risk_loader.current_config()
    original = cfg['weights'].get('lateral')
    # Send feedback vote (true_positive) for factor 'lateral'
    resp = client.post('/api/v1/feedback/decision', json={
        'decision_id': 'dec-test-1',
        'label': 'true_positive',
        'factors': ['lateral'],
        'apply_calibration': True
    }, headers={'x-api-key': 'devkey123'})
    assert resp.status_code == 200, resp.text
    updated_cfg = risk_loader.current_config()
    new_val = updated_cfg['weights'].get('lateral')
    assert new_val >= original, f"Expected weight to increase or stay, got {new_val} < {original}"
    # Second false_positive vote should decrease
    resp2 = client.post('/api/v1/feedback/decision', json={
        'decision_id': 'dec-test-2',
        'label': 'false_positive',
        'factors': ['lateral'],
        'apply_calibration': True
    }, headers={'x-api-key': 'devkey123'})
    assert resp2.status_code == 200, resp2.text
    updated_cfg2 = risk_loader.current_config()
    new_val2 = updated_cfg2['weights'].get('lateral')
    assert new_val2 <= new_val, f"Expected weight to decrease or stay, got {new_val2} > {new_val}"

def test_replay_scenario_precision_recall():
    resp = client.get('/api/v1/replay/scenario', params={'name': 'test_scenario'})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # In test scenario: tp=1 (e1), fp=1 (e2), fn=1 (e3 missing factors), tn=1 (e4)
    counts = data['counts']
    assert counts['tp'] == 1
    assert counts['fp'] == 1
    assert counts['fn'] == 1
    assert counts['tn'] == 1
    assert counts['total'] == 4
    # precision = 1/(1+1)=0.5; recall = 1/(1+1)=0.5
    assert abs(data['precision'] - 0.5) < 1e-6
    assert abs(data['recall'] - 0.5) < 1e-6
