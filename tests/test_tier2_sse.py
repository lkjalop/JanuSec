import os
import json
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_tier2_sse_streaming_json():
    # Ensure mock mode is enabled before importing LLM client module
    os.environ['LLM_MOCK'] = '1'
    # Import router lazily to ensure env var is set first
    from src.api import tier2_endpoints as t2

    app = FastAPI()
    app.include_router(t2.router)
    client = TestClient(app)

    payload = {
        'assessment_id': 'A1',
        'rows': [
            {'row_index': 1, 'summary': 'dns qname malicious.example.com', 'type': 'dns', 'qname': 'malicious.example.com'},
        ],
    }

    resp = client.post('/api/v1/csv/tier2_sse', json=payload)
    assert resp.status_code == 200
    body = resp.content.decode('utf-8')
    parts = [line[len('data: '):] for line in body.splitlines() if line.startswith('data: ')]
    assert parts, 'No SSE data frames found'
    combined = ''
    for p in parts:
        try:
            obj = json.loads(p)
            combined += obj.get('chunk','')
        except Exception:
            combined += p

    parsed = json.loads(combined)
    assert 'verdict' in parsed
    assert 'evidence' in parsed
