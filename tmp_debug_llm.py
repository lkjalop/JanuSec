import os
import json
from fastapi.testclient import TestClient
from src.api.app import create_app
from src.api.deep_analyze_endpoints import REPORT_STORE

os.environ['LLM_MOCK'] = '1'
app = create_app()
client = TestClient(app)

payload = {
    'rows': [
        {'ip': '8.8.4.4', 'file_hash': 'a1'},
        {'ip': '8.8.8.8', 'file_hash': 'a2'},
    ],
    'options': {'auto_llm': True},
}
resp = client.post('/api/v1/assessments/deep_analyze', json=payload)
print('deep_analyze status', resp.status_code)
try:
    print('deep_analyze body', json.dumps(resp.json(), indent=2))
except Exception:
    print('deep_analyze body raw:', resp.text)

aid = None
try:
    aid = resp.json().get('assessment_id')
except Exception:
    pass
if not aid and REPORT_STORE:
    aid = next(iter(REPORT_STORE.keys()))
print('assessment_id', aid)
print('REPORT_STORE keys:', list(REPORT_STORE.keys()))

if aid:
    enqueue = client.post(f'/api/v1/assessments/{aid}/llm/enqueue', json={'limit': 1})
    print('enqueue status', enqueue.status_code)
    try:
        print('enqueue body', json.dumps(enqueue.json(), indent=2))
    except Exception:
        print('enqueue raw:', enqueue.text)
