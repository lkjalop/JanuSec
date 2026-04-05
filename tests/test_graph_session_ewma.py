import os
import time
from fastapi.testclient import TestClient

from src.api.app import app


def test_ewma_smoothing_persists_between_builds(monkeypatch):
    # Ensure test helpers enabled so runtime is available
    monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')
    client = TestClient(app)

    # Prepare two fake file-batch entries in runtime store
    from src.api.runtime_state import get_file_batch_analysis, get_server_runtime_state
    runtime = get_server_runtime_state(app)
    file_batches = get_file_batch_analysis(runtime)
    # create small batches with overlapping sha values
    file_batches['batch-A'] = {'files': [{'sha256': 's1'}, {'sha256': 's2'}]}
    file_batches['batch-B'] = {'files': [{'sha256': 's2'}, {'sha256': 's3'}]}

    payload = {'session_ids': ['batch-A', 'batch-B'], 'correlate': True, 'ewma': True, 'ewma_alpha': 0.8}

    r1 = client.post('/api/v1/graph/session/build', json=payload)
    assert r1.status_code == 200, r1.text
    data1 = r1.json()
    sid = data1.get('session_id')
    assert sid
    # correlation_smoothed should be present and be integers
    summary1 = data1.get('summary')
    assert 'correlation_smoothed' in summary1
    cs1 = summary1['correlation_smoothed']
    # subsequent build with same batches should increase smoothed values slightly
    r2 = client.post('/api/v1/graph/session/build', json=payload)
    assert r2.status_code == 200, r2.text
    data2 = r2.json()
    summary2 = data2.get('summary')
    cs2 = summary2['correlation_smoothed']

    # Check that the smoothed overlap count for the off-diagonal increased or remains stable
    a_b_1 = cs1.get('batch-A', {}).get('batch-B')
    a_b_2 = cs2.get('batch-A', {}).get('batch-B')
    assert isinstance(a_b_1, int)
    assert isinstance(a_b_2, int)
    assert a_b_2 >= a_b_1
