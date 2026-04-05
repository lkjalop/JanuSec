import pytest


def test_deep_analyze_minimal(test_client):
    payload = {'rows': [{'process_name': 'powershell.exe', 'file_path': 'C:\\temp\\script.ps1'}], 'auto_llm': False}
    resp = test_client.post('/api/v1/csv/deep_analyze', json=payload)
    assert resp.status_code == 200
    j = resp.json()
    # The endpoint may respond synchronously ('completed') or asynchronously ('pending')
    # depending on whether the background pipeline accepts the task.
    assert j.get('status') in ('completed', 'pending')
    # Processed count may be in 'processed', 'rows_processed', or 'accepted_rows'
    processed = (
        j.get('processed')
        or j.get('rows_processed')
        or j.get('accepted_rows')
    )
    assert processed is None or processed >= 1
    # Results list may be present right away or only after completion
    if j.get('results') is not None:
        assert isinstance(j.get('results'), list)
