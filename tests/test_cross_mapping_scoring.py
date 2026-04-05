import time
from src.api.graph_endpoints import build_graph_session
from src.api.runtime_state import ServerRuntime, get_file_batch_analysis


def test_cross_mapping_scoring_continuous(tmp_path, monkeypatch):
    # Prepare runtime file batch analysis with two batches and mapping
    runtime = ServerRuntime()
    fa = get_file_batch_analysis(runtime)
    fa['batch-a'] = {'files': [{'sha256': 'a1', 'observed_ts': time.time()}]}
    fa['batch-b'] = {'files': [{'sha256': 'b1', 'observed_ts': time.time()}]}
    payload = {'session_ids': ['batch-a', 'batch-b'], 'mapping': {'u':'user','h':'host','f':'file'}}
    # Call builder directly (no request)
    out = build_graph_session(payload)
    assert 'summary' in out
    s = out['summary']
    assert any(f.get('factor') == 'cross_mapping_correlation' for f in s.get('factors', []))
    # continuous score should be present and between 0 and 1
    cms = [f for f in s.get('factors', []) if f.get('factor') == 'cross_mapping_correlation'][0]
    assert 0.0 <= float(cms.get('score', 0.0)) <= 1.0
