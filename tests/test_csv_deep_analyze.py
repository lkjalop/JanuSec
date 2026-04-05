import pytest


def test_deep_analyze_minimal(test_client):
    payload = {'rows': [{'process_name': 'powershell.exe', 'file_path': 'C:\\temp\\script.ps1'}], 'auto_llm': False}
    resp = test_client.post('/api/v1/csv/deep_analyze', json=payload)
    assert resp.status_code == 200
    j = resp.json()
    assert j.get('status') == 'completed'
    assert j.get('processed') == 1
    assert isinstance(j.get('results'), list)
