import time
from fastapi.testclient import TestClient
from src.api.app import app


def test_composite_chain_with_non_missing_batch(monkeypatch):
    monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')
    client = TestClient(app)
    # Seed one batch with a file that has factors to ensure non-missing behavior
    from src.api.runtime_state import get_file_batch_analysis, get_server_runtime_state
    runtime = get_server_runtime_state(app)
    fb = get_file_batch_analysis(runtime)
    fb.clear()
    fb['batch-1'] = {'files': [{'sha256': 'hx1', 'observed_ts': time.time(), 'factors': ['high_entropy']}]}

    payload = {
        'session_ids': ['batch-1'],
        'correlate': True,
        'ewma': False,
        'mapping': {'sha256': 'valueA'}
    }
    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    summary = data['summary']
    assert 'composite_chain' in summary
    assert isinstance(summary['composite_chain'], list)
    assert summary['mapping_stats'], 'expected mapping_stats when mapping provided'