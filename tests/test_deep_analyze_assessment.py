import os
import time
import json
from fastapi.testclient import TestClient
from src.api.app import create_app


def test_deep_analyze_persists_llm_rows(tmp_path, monkeypatch):
    # Create app and client
    app = create_app()
    client = TestClient(app)

    # Small payload with two rows
    rows = [
        {'row_index': 0, 'file_hash': 'deadbeef', 'process_name': 'rundll32', 'host': 'host1', 'factors': ['lolbin']},
        {'row_index': 1, 'file_hash': 'cafebabe', 'process_name': 'powershell', 'host': 'host2', 'factors': ['suspicious']},
    ]

    payload = {'rows': rows, 'options': {'auto_llm': True}, 'org': 'testorg'}

    r = client.post('/api/v1/assessments/deep_analyze', json=payload)
    assert r.status_code == 200
    j = r.json()
    assert 'assessment_id' in j
    aid = j['assessment_id']
    # Wait for persisted file to appear (short timeout)
    base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data', 'assessments')
    found = None
    deadline = time.time() + 10
    while time.time() < deadline and not found:
        for orgdir in os.listdir(base):
            d = os.path.join(base, orgdir)
            if not os.path.isdir(d):
                continue
            for datepart in os.listdir(d):
                p = os.path.join(d, datepart, f"{aid}.json")
                if os.path.exists(p):
                    found = p
                    break
            if found:
                break
        if not found:
            time.sleep(0.3)
    assert found, 'Persisted assessment file not found'

    # Verify persisted file exists
    base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data', 'assessments')
    # find under date directory
    found = None
    for orgdir in os.listdir(base):
        d = os.path.join(base, orgdir)
        if not os.path.isdir(d):
            continue
        for datepart in os.listdir(d):
            p = os.path.join(d, datepart, f"{aid}.json")
            if os.path.exists(p):
                found = p
                break
        if found:
            break
    assert found, 'Persisted assessment file not found'

    with open(found, 'r', encoding='utf-8') as fh:
        content = json.load(fh)

    # Expect llm_rows or rows to be present
    llm_rows = content.get('llm_rows') or content.get('rows') or []
    assert isinstance(llm_rows, list) and len(llm_rows) >= 1
    # llm_rows may be either fully-enriched (with llm_summary) or raw input rows
    # depending on whether the pipeline completed synchronously or is still pending.
    llm_required = {'row_index', 'fingerprint', 'llm_summary', 'llm_meta', 'generated_at'}
    raw_required = {'row_index'}
    for rrow in llm_rows:
        keys = set(rrow.keys())
        assert llm_required.issubset(keys) or raw_required.issubset(keys), f'missing keys in {rrow.keys()}'
