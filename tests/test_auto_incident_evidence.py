import time
from src.api.graph_endpoints import build_graph_session
from src.api.runtime_state import ServerRuntime, get_file_batch_analysis
from src.incidents.aggregator import GLOBAL_INCIDENTS


def test_auto_incident_evidence_and_metadata(monkeypatch):
    # Prepare runtime with two batches that will produce multiple factors
    runtime = ServerRuntime()
    fb = get_file_batch_analysis(runtime)
    fb['batch-x'] = {'files': [{'sha256': 'hx1', 'observed_ts': time.time(), 'factors': ['high_entropy']}, {'sha256': 'hx2', 'observed_ts': time.time()}]}
    fb['batch-y'] = {'files': [{'sha256': 'hy1', 'observed_ts': time.time(), 'factors': ['signature_mismatch']}, {'sha256': 'hy2', 'observed_ts': time.time()}]}
    payload = {'session_ids': ['batch-x', 'batch-y'], 'mapping': {'user':'user','host':'host','file':'file'}, 'correlate': True, 'ewma': False, 'ewma_alpha': 0.6}
    out = build_graph_session(payload)
    assert 'summary' in out
    s = out['summary']
    # If auto-generated, attach auto_incident_id and auto_incident_evidence
    if s.get('auto_incident_id'):
        iid = s.get('auto_incident_id')
        # Find incident in GLOBAL_INCIDENTS
        incs = GLOBAL_INCIDENTS.list_incidents()
        assert any(i['id'] == iid for i in incs)
        inc = next(i for i in incs if i['id'] == iid)
        # Should include evidence keys persisted earlier
        assert 'playbook' in inc or 'ingested_events_full' in inc or 'framework_enrichment' in inc
        # session should include evidence link and metadata.chain_scoring
        assert s.get('auto_incident_evidence') is not None
        assert 'chain_scoring' in s.get('metadata', {}) or s.get('mapping_stats') is not None
