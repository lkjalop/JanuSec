from importlib import import_module
from fastapi.testclient import TestClient
mod = import_module('src.api.app')
app = mod.app
client = TestClient(app)
print('GET /api/v1/config/assessment_defaults')
r = client.get('/api/v1/config/assessment_defaults')
print('status=', r.status_code)
print('body=', r.text)
print('POST /api/v1/assessments/save_metadata')
r2 = client.post('/api/v1/assessments/save_metadata', json={'org':'acme','assessor':'alice','ts':1700000000})
print('status=', r2.status_code)
print('body=', r2.text)
