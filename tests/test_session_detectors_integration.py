import time
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})
from src.api.runtime_state import get_server_runtime_state, get_file_batch_analysis


def test_session_build_with_detectors_uplift(monkeypatch):
    monkeypatch.setenv('TEST_HELPERS_ENABLED','1')
    client = TestClient(app)
    runtime = get_server_runtime_state(app)
    # Seed NXDOMAIN ratio
    runtime.nx_rate_tracker.clear()
    runtime.nx_rate_tracker['zeek:exfil.example.com'].extend([True]*30 + [False]*5)
    runtime.dns_query_samples = {'zeek:exfil.example.com': [f"d{i}x{i}.exfil.example.com" for i in range(15)]}
    # Seed file hash history (make one hash common, one rare)
    runtime.file_hash_factors.clear()
    runtime.file_hash_factors['hcommon'] = 120  # frequent
    # Create file batch with a rare hash and high-entropy factor
    fb = get_file_batch_analysis(runtime)
    fb.clear()
    fb['batch-A'] = {'files': [
        {'sha256': 'hrareZ', 'observed_ts': time.time(), 'factors': ['high_entropy']},
        {'sha256': 'hcommon', 'observed_ts': time.time()},
    ]}
    payload = {
        'session_ids': ['batch-A'],
        'correlate': True,
        'ewma': False,
        'mapping': {'sha256': 'abc', 'hostname': 'srv1'}
    }
    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200, r.text
    summary = r.json()['summary']
    factors = summary['factors']
    # Expect dns_exfil factor
    assert any(f.get('factor') == 'dns_exfil' for f in factors), factors
    # Expect file_hash_rarity factor
    assert any(f.get('factor') == 'file_hash_rarity' for f in factors), factors
    # Confidence should be uplifted beyond baseline
    assert summary['confidence'] >= 0.6
    # Verdict should be SUSPECT due to high scoring dns_exfil factor
    assert summary['verdict'] == 'SUSPECT'
    # composite_chain present
    assert 'composite_chain' in summary and isinstance(summary['composite_chain'], list)
