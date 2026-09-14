import json
from fastapi.testclient import TestClient
from src.api.app import app


def test_ask_for_logs_endpoint():
    client = TestClient(app)
    payload = {'recipient': 'ops@example.com', 'reason': 'Need logs for triage'}
    headers = {'x-api-key': 'devkey123'}
    r = client.post('/api/v1/reports/rep-123/ask_for_logs', json=payload, headers=headers)
    assert r.status_code == 200
    j = r.json()
    assert j.get('ok') is True
    assert 'message' in j
    assert 'to' in j['message']


def test_prewarm_llm_no_crash():
    client = TestClient(app)
    r = client.post('/api/v1/enrichment/llm/prewarm', json={'model': 'llama3:8b'})
    assert r.status_code == 200
    j = r.json()
    assert 'model' in j
