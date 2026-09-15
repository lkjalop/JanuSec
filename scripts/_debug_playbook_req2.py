import sys, os
os.environ['PYTEST_CURRENT_TEST'] = '1'
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
from fastapi import FastAPI
from src.api.playbook_approval_endpoints import router as approval_router
app = FastAPI(); app.include_router(approval_router)
client = TestClient(app)
headers={'x-api-key':'testkey123'}
# Try as dict
r = client.post('/api/v1/playbook/request', json={'action':'restart_collector','target':'demo_collector'}, headers=headers)
print('-> dict attempt')
print('status', r.status_code)
try:
    print('json ->', r.json())
except Exception:
    print('text ->', r.text)

print('\n-> list attempt')
r2 = client.post('/api/v1/playbook/request', json=[{'action':'restart_collector','target':'demo_collector'}], headers=headers)
print('status', r2.status_code)
try:
    print('json ->', r2.json())
except Exception:
    print('text ->', r2.text)
print('status', r.status_code)
try:
    print('json ->', r.json())
except Exception as e:
    print('json parse error', e)
    print('text ->', r.text)
    print('headers ->', r.headers)
