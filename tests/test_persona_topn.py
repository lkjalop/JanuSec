import json
import os
from fastapi.testclient import TestClient

from src.api.app import app

client = TestClient(app)


def make_report_with_many_items(n=50):
    # Build a minimal report with repeated items for summary signals
    report = {
        'report_id': 'r-test-topn',
        'verdict': {'final_verdict': 'REVIEW', 'final_confidence': 0.5},
        'network_highlights': {},
        'summary': {},
        'verdict_stats': {},
        'risk_quantification': {'severity': 'MEDIUM'},
    }
    # Helpers that persona_views expects: top5_* will operate on report; we add lists
    report['top_mitre'] = [{'technique': f'T{i}'} for i in range(n)]
    # For persona_views we rely on summary functions; put arrays under keys used by generator
    report['factors'] = [{'name': f'f{i}'} for i in range(n)]
    report['iocs'] = [{'ioc': f'i{i}'} for i in range(n)]
    report['impacted_entities'] = [{'entity': f'e{i}'} for i in range(n)]
    report['recommended_actions'] = [{'act': f'a{i}'} for i in range(n)]
    return report


def test_post_persona_view_respects_top_n():
    rpt = make_report_with_many_items(40)
    # ask for top_n = 5
    resp = client.post('/api/v1/reports/persona_view?persona=executive&disclosure_level=2&top_n=5', json=rpt)
    assert resp.status_code == 200, resp.text
    j = resp.json()
    # summary_signals keys should be present and limited to 5
    ss = j.get('summary_signals') or {}
    assert len(ss.get('risk_drivers', [])) <= 5
    assert len(ss.get('factors', [])) <= 5
    assert len(ss.get('iocs', [])) <= 5


def test_get_persona_view_snapshot_respects_top_n(tmp_path):
    # write snapshot file expected by GET endpoint
    rpt = make_report_with_many_items(30)
    snap_dir = Path = tmp_path
    reports_dir = os.path.join('reports', 'snapshots')
    os.makedirs(reports_dir, exist_ok=True)
    filepath = os.path.join(reports_dir, 'r-test-topn.json')
    with open(filepath, 'w', encoding='utf-8') as fh:
        json.dump({'payload': rpt}, fh)
    try:
        resp = client.get('/api/v1/reports/r-test-topn/persona_view?persona=executive&disclosure_level=2&top_n=3')
        assert resp.status_code == 200, resp.text
        j = resp.json()
        ss = j.get('summary_signals') or {}
        assert len(ss.get('risk_drivers', [])) <= 3
        assert len(ss.get('factors', [])) <= 3
    finally:
        try:
            os.remove(filepath)
        except Exception:
            pass
