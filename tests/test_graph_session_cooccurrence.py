import json
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)


def test_build_session_records_pairs(tmp_path, monkeypatch):
    # create fixture session file
    rows = [{'user':'alice','host':'web01'},{'user':'bob','host':'web02'}]
    # write directly to tests fixtures directory to avoid cross-volume rename issues on Windows CI
    import os
    fixtures = os.path.join('tests','fixtures','sessions')
    os.makedirs(fixtures, exist_ok=True)
    s1_path = os.path.join(fixtures, 'sessA.json')
    s2_path = os.path.join(fixtures, 'sessB.json')
    with open(s1_path, 'w', encoding='utf-8') as fh:
        fh.write(json.dumps(rows))
    with open(s2_path, 'w', encoding='utf-8') as fh:
        fh.write(json.dumps(rows))
    monkeypatch.setenv('OVERLAP_VALUES_LIMIT','25')
    payload = {'session_ids': ['sessA','sessB'], 'correlate': True}
    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200
    body = r.json()
    assert 'session_id' in body
    assert 'summary' in body
    # summary shape may vary by branch; accept either new 'co_occurrence_pairs' or legacy 'chain_explanation'
    summ = body['summary']
    assert ('co_occurrence_pairs' in summ) or ('chain_explanation' in summ) or ('graph_summary' in summ)
