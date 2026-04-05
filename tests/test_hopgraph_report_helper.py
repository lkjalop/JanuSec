import os
from fastapi.testclient import TestClient

os.environ.setdefault('STRICT_API_KEY_ENFORCEMENT', '0')

from src.api.app import app  # noqa

client = TestClient(app)


def test_hopgraph_report_endpoint():
    session_id = 'session-hopgraph-demo'
    row = {
        'event_id': 'evt-hopgraph-1',
        'user': 'alice',
        'host': 'workstation-01',
        'file_hash': 'deadbeef0011223344',
        'verdict': 'SUSPICIOUS',
        'confidence': 0.9,
        'factors': ['mapping_semantics_rich', 'entity_diversity_high']
    }
    analysis = client.post('/api/v1/csv/analyze_row', json={'row': row})
    assert analysis.status_code == 200, analysis.text
    session_summary = {
        'session_ids': ['batch-alpha', 'batch-beta'],
        'mapping_stats': {'user': 2, 'host': 2, 'file_hash': 1, 'ip': 0, 'domain': 1},
        'mapping_semantics_score': 0.6,
        'domain_diversity_score': 0.5,
        'verdict': 'escalate',
        'confidence': 0.8
    }
    session_explain = {
        'session_id': session_id,
        'confidence': 0.8,
        'verdict': 'escalate',
        'key_factors': ['mapping_semantics_rich'],
        'domains_present': ['identity'],
        'domain_diversity_score': 0.5,
        'mapping_semantics_score': 0.6,
        'confidence_breakdown': {'base': 0.7, 'final': 0.8},
        'overlap_hotspots': [{'a': 'batch-alpha', 'b': 'batch-beta', 'fields': 2}],
        'narrative': 'Synthetic narrative for unit test.'
    }
    payload = {
        'session_id': session_id,
        'rows': [row],
        'row_analysis': [{'row': row, 'analysis': analysis.json()}],
        'session_summary': session_summary,
        'session_explain': session_explain,
        'batch_meta': {'org': 'UnitTest'}
    }
    resp = client.post('/api/v1/assessments/hopgraph_report', json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data['artifact_count'] == 1
    report = data['report']
    hop_summary = report.get('hopgraph_summary') or {}
    assert session_id in hop_summary
    assert hop_summary[session_id]['samples'] == 1
