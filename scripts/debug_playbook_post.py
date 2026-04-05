import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
import os
os.environ['PYTEST_CURRENT_TEST'] = '1'
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)
headers = {'x-api-key': 'testkey123'}
resp = client.post('/api/v1/playbook/request', json={'action':'restart_collector','target':'demo_collector'}, headers=headers)
print('status', resp.status_code)
try:
    print('json:', resp.json())
except Exception as e:
    print('response text:', resp.text)
