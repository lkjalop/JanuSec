import os
import json
import time
import pytest

from fastapi.testclient import TestClient

from src.api.app import create_app


@pytest.fixture
def client():
    # ensure mock LLM mode for deterministic summaries
    os.environ['LLM_MOCK'] = '1'
    app = create_app()
    with TestClient(app) as c:
        yield c


def test_deep_analyze_returns_llm_summary(client):
    payload = {
        "org": "unittest",
        "rows": [
            {"row_index": 0, "process_name": "testproc", "sha256": "0000000000000000000000000000000000000000000000000000000000000000"}
        ],
        "options": {"auto_llm": True}
    }
    r = client.post('/api/v1/csv/deep_analyze', json=payload)
    assert r.status_code == 200, r.text
    j = r.json()
    aid = j.get('assessment_id') or j.get('report_id') or j.get('id')
    assert aid, 'no assessment id returned'

    # poll rows endpoint for a short time until llm_rows appear
    rows = None
    for _ in range(10):
        rr = client.get(f'/api/v1/assessments/{aid}/rows')
        if rr.status_code == 200:
            data = rr.json()
            rows = data.get('rows') or data.get('llm_rows') or []
            if rows:
                break
        time.sleep(0.2)
    assert rows is not None and len(rows) > 0, 'no rows returned from assessment rows endpoint'
    # Ensure each flagged row has an llm_summary string longer than 10 characters
    for row in rows:
        summary = row.get('llm_summary') or row.get('summary') or row.get('llm_output')
        assert summary, f'Row missing llm summary: {row}'
        if isinstance(summary, dict):
            # if mock returned structure, extract text
            summary_text = summary.get('text') or summary.get('summary') or ''
        else:
            summary_text = str(summary)
        assert len(summary_text.strip()) > 10, f'llm_summary too short: {summary_text}'
import os
import time
import json
from fastapi.testclient import TestClient


def test_deep_analyze_llm_summaries_present(tmp_path, monkeypatch):
    # Ensure LLM mock is enabled for deterministic output and load app in lite mode
    monkeypatch.setenv('LLM_MOCK', '1')
    monkeypatch.setenv('PLATFORM_LITE_INIT', '1')
    # Import app factory after env vars set to avoid heavy optional imports
    from src.api.app import create_app
    app = create_app()
    client = TestClient(app)

    # Prepare a small set of rows with simple signals
    rows = [
        {'process_name': 'svc.exe', 'file_path': 'C:\\Windows\\System32\\svc.exe', 'sha256': 'aaa', 'host': 'host1', 'avPositives': 12},
        {'process_name': 'unknown.exe', 'file_path': 'C:\\Temp\\unknown.exe', 'sha256': 'bbb', 'host': 'host2', 'avPositives': 0},
    ]

    payload = {'rows': rows, 'options': {'auto_llm': True}, 'org': 'test-org'}
    resp = client.post('/api/v1/csv/deep_analyze', json=payload)
    assert resp.status_code == 200
    j = resp.json()
    aid = j.get('assessment_id') or j.get('report_id')
    assert aid

    # Poll assessment until rows available or timeout
    got = None
    deadline = time.time() + 5
    while time.time() < deadline:
        r = client.get(f'/api/v1/assessments/{aid}')
        assert r.status_code == 200
        data = r.json()
        rows_payload = data.get('llm_rows') or data.get('rows') or []
        if rows_payload:
            got = rows_payload
            break
        time.sleep(0.2)

    assert got is not None, 'No llm_rows produced by deep_analyze'
    # Ensure every flagged/llm row has a non-empty llm_summary of decent length
    for rr in got:
        summary = rr.get('llm_summary') or rr.get('summary') or rr.get('llm_output')
        assert summary is not None, f'Row {rr.get("row_index")} missing llm summary'
        text = summary if isinstance(summary, str) else json.dumps(summary)
        assert len(text.strip()) > 10, f'Row {rr.get("row_index")} llm_summary too short: {text}'
