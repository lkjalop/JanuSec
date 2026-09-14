import os
import json
import pytest
from src.api.app import app


def test_graph_session_auto_llm(test_client):
    # Ensure test helpers enabled so LLM runs synchronously
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    payload = {
        'session_ids': ['batch-overlap-a','batch-overlap-b'],
        'correlate': True,
        'ewma': False,
        'meta': {'auto_llm': True, 'org': 'test-org'}
    }
    r = test_client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert 'session_id' in data
    session_id = data.get('session_id')
    # retrieve full session and assert llm_summary present
    r2 = test_client.get(f'/api/v1/graph/session/{session_id}')
    assert r2.status_code == 200, r2.text
    rec = r2.json()
    summary = rec.get('summary') or {}
    assert 'llm_summary' in summary and summary['llm_summary'], 'llm_summary missing or empty'
