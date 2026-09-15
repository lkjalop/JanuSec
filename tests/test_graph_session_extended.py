import os
from fastapi.testclient import TestClient
from src.api.app import app


def test_session_build_extended_fields(monkeypatch):
    monkeypatch.setenv('TEST_HELPERS_ENABLED','1')
    client = TestClient(app)

    payload = {
        'session_ids': ['batch-X','batch-Y'],
        'correlate': True,
        'ewma': True,
        'ewma_alpha': 0.6,
        'mapping': {'sha256': 'valueA', 'hostname': 'srv1', 'username': 'alice'}
    }
    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    summary = data['summary']
    assert 'correlation_smoothed' in summary
    assert 'mapping_stats' in summary and summary['mapping_stats']
    # batch_missing factors should appear (fixtures absent)
    factors = summary['factors']
    bm = [f for f in factors if isinstance(f, dict) and f.get('factor')=='batch_missing']
    assert bm, 'expected batch_missing factor objects'
    # composite_chain optional list present when correlation + diversity apply
    assert 'composite_chain' in summary
    # Confidence within sane bounds
    assert 0.0 < summary['confidence'] <= 0.95