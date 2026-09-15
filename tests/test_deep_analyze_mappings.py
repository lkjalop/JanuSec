import json
from fastapi.testclient import TestClient
from src.api.app import create_app


def test_deep_analyze_mappings_present():
    app = create_app()
    client = TestClient(app)
    payload = {'rows': [{'ip':'10.0.0.5','file_hash':'deadbeef','user':'admin'}], 'options': {'auto_llm': False}}
    r = client.post('/api/v1/assessments/deep_analyze', json=payload)
    assert r.status_code == 200
    body = r.json()
    assert 'report_id' in body
    assert 'results' in body
    # canonical and mappings should be present
    assert 'canonical' in body
    assert 'mappings' in body
    assert 'mitre' in body['mappings']
