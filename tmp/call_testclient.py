from importlib import import_module
from fastapi.testclient import TestClient
mod = import_module('src.api.app')
app = mod.app
client = TestClient(app)
resp = client.get('/api/v1/config/assessment_defaults')
print('STATUS', resp.status_code)
print('BODY', resp.text)
resp2 = client.post('/api/v1/assessments/save_metadata', json={'org':'acme','assessor':'alice','ts':1700000000})
print('POST STATUS', resp2.status_code)
print('POST BODY', resp2.text)
