import re, time
from fastapi.testclient import TestClient
from src.api.app import app

# Simple FP ratio metric test: ensure labeling updates ratio after next session build

def test_fp_ratio_metric_updates():
    client = TestClient(app)
    # Seed first batch with high_entropy factor
    from src.api.runtime_state import get_server_runtime_state, get_file_batch_analysis
    runtime = get_server_runtime_state(app)
    fb = get_file_batch_analysis(runtime)
    fb.clear()
    fb['batch-A'] = {'files': [{'sha256': 'aaa1', 'factors': ['high_entropy']}]}
    r1 = client.post('/api/v1/graph/session/build', json={'session_ids': ['batch-A'], 'correlate': True, 'ewma': False})
    assert r1.status_code == 200
    sess1 = r1.json()['summary']['session_id']
    # Label high_entropy as false_positive
    lab = client.post('/api/v1/factors/label', json={'session_id': sess1, 'factor': 'high_entropy', 'label': 'false_positive'})
    assert lab.status_code == 200
    # Build second session to trigger ratio update (another occurrence)
    r2 = client.post('/api/v1/graph/session/build', json={'session_ids': ['batch-A'], 'correlate': True, 'ewma': False})
    assert r2.status_code == 200
    # Scrape metrics
    m = client.get('/metrics')
    assert m.status_code == 200
    text = m.text
    # Find gauge line; pattern like: detector_factor_fp_ratio{factor="high_entropy"} 0.5
    pattern = re.compile(r'detector_factor_fp_ratio\{factor="high_entropy".*?\} (\d+\.\d+|\d+)')
    match = pattern.search(text)
    assert match, f"FP ratio gauge line not found in metrics scrape:\n{text[:500]}"
    val = float(match.group(1))
    assert 0.45 <= val <= 0.55, f"Expected ~0.5 ratio after 1 FP label out of 2 occurrences, got {val}"
