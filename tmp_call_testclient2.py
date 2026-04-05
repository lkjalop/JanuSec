from fastapi.testclient import TestClient
from src.api.app import app
client = TestClient(app)
resp = client.post('/api/v1/graph/session/build', json={'session_ids':['fixed-A-1','fixed-B-2','fixed-C-3'],'correlate':True,'ewma':False}, headers={'X-Roles':'analyst'})
print(resp.status_code)
print(resp.text[:200])
