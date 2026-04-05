import json
import os
from fastapi.testclient import TestClient
from src.api.app import create_app
from src.api.deep_analyze_endpoints import REPORT_STORE

os.environ['LLM_MOCK'] = '1'
app = create_app()
client = TestClient(app)

payload = {'rows':[{'ip':'8.8.8.8'}], 'options':{'auto_llm': True}}
resp = client.post('/api/v1/assessments/deep_analyze', json=payload)
print('status', resp.status_code)
try:
    print('body', json.dumps(resp.json(), indent=2))
except Exception:
    print('body raw', resp.text)

print('\nREPORT_STORE keys:', list(REPORT_STORE.keys()))
base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data', 'assessments')
index_dir = os.path.join(base, 'index')
print('index dir exists?', os.path.exists(index_dir))
if os.path.exists(index_dir):
    print('index files:', os.listdir(index_dir)[:20])
