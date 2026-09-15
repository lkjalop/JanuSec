from fastapi.testclient import TestClient
from fastapi import FastAPI
from src.api.playbook_approval_endpoints import router as approval_router
app = FastAPI(); app.include_router(approval_router)
client = TestClient(app)
headers={'x-api-key':'testkey123'}
r = client.post('/api/v1/playbook/request', json={'action':'restart_collector','target':'demo_collector'}, headers=headers)
print('status', r.status_code)
try:
	print('json ->', r.json())
except Exception:
	print('text ->', r.text)
