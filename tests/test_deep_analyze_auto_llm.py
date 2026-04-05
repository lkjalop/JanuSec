import os
from fastapi.testclient import TestClient
from src.api.app import create_app


def test_auto_llm_includes_summary():
    os.environ['LLM_MOCK'] = '1'
    app = create_app()
    client = TestClient(app)
    payload = {'rows': [{'ip':'8.8.8.8','file_hash':'cafebabe'}], 'options': {'auto_llm': True}}
    r = client.post('/api/v1/assessments/deep_analyze', json=payload)
    assert r.status_code == 200
    body = r.json()
    assert 'canonical' in body
    assert 'llm_summary' in body['canonical']
