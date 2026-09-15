import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.api.playbook_approval_endpoints import router as approval_router

app = FastAPI()
app.include_router(approval_router)
client = TestClient(app)
resp = client.post('/api/v1/playbook/request', json={'action':'restart_collector','target':'demo_collector'})
print('status', resp.status_code)
print('body', resp.text)
