import os
import time
import pytest


def test_graph_session_auto_llm_async(test_client):
    # Ensure TEST_HELPERS_DISABLED for background scheduling path (explicitly unset)
    if 'TEST_HELPERS_ENABLED' in os.environ:
        del os.environ['TEST_HELPERS_ENABLED']
    payload = {
        'session_ids': ['batch-overlap-a','batch-overlap-b'],
        'correlate': True,
        'ewma': False,
        'meta': {'auto_llm': True, 'org': 'async-org'}
    }
    r = test_client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    session_id = data.get('session_id')
    assert session_id
    # Poll briefly for up to 6 seconds for background llm_summary to appear
    found = False
    for _ in range(12):
        r2 = test_client.get(f'/api/v1/graph/session/{session_id}')
        assert r2.status_code == 200, r2.text
        rec = r2.json()
        summary = rec.get('summary') or {}
        if summary.get('llm_summary'):
            found = True
            break
        time.sleep(0.5)
    assert found, 'expected background llm_summary to appear within timeout'
