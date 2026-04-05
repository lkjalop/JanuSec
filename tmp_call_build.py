from src.api.app import create_app
from fastapi.testclient import TestClient
app=create_app()
client=TestClient(app)
payload={'session_ids':['a','b'],'ewma':True,'ewma_alpha':1.5}
r=client.post('/api/v1/graph/session/build', json=payload)
print('status', r.status_code)
try:
    print('json:', r.json())
except Exception:
    print('text:', r.text)
