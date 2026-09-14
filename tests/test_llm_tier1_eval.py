import os
import json
from fastapi.testclient import TestClient
from src.api.app import create_app


def test_tier1_summarize_and_evaluator(tmp_path, monkeypatch):
    # Ensure a clean claims DB path
    dbp = tmp_path / 'claims.db'
    monkeypatch.setenv('LLM_CLAIMS_DB', str(dbp))
    app = create_app({'mode': 'test'})
    client = TestClient(app)

    payload = {
        'decision_id': 'd-1',
        'top_factors': [
            {'type': 'proc_spawn', 'contribution': 0.9},
            {'type': 'susp_cmd', 'contribution': 0.7},
        ],
        'related_events': [{'id': 'e1', 'summary': 'process spawned mshta.exe'}]
    }
    r = client.post('/api/v1/llm/tier1/summarize', json=payload)
    assert r.status_code == 200
    j = r.json()
    assert 'summary' in j
    summary = j['summary']
    # older router returns a dict summary, newer returns list of bullets
    if isinstance(summary, dict):
        # Accept dict-shaped summary (legacy) by ensuring keys exist
        assert any(k in summary for k in ('what', 'why', 'recommended_actions', 'recommended_actions'))
    else:
        assert isinstance(summary, list)
    # run evaluator CLI import to compute stats
    from src.eval.llm_evaluator import compute_precision_report
    rep = compute_precision_report()
    assert 'total' in rep
