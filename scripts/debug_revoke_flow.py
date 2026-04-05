import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)
headers = {'x-api-key': 'testkey123'}
# request
r = client.post('/api/v1/playbook/request', json={'action':'restart_collector','target':'demo_collector'}, headers=headers)
token = r.json().get('token')
print('token', token)
# approve
apr = client.post('/api/v1/playbook/approve', params={'token': token, 'approver': 'tester'}, headers=headers)
print('approve status', apr.status_code, apr.text)
# revoke
rv = client.post('/api/v1/playbook/revoke', params={'token': token, 'reason': 'no longer needed'}, headers=headers)
print('revoke status', rv.status_code, rv.text)
