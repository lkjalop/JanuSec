import os, json
from fastapi.testclient import TestClient
os.environ['ADMIN_UI_TOKEN'] = 'admin-secret-test'
os.environ['API_KEYS_JSON'] = json.dumps([{'key':'testkey123','scopes':['feedback.write','factors.search','models.promote','models.alias']}])
# import app after env
from src.api.app import app
client = TestClient(app)
files = {'file': ('m.json', json.dumps({'type':'sigmoid','k':1.2,'x0':0.5}), 'application/json')}
headers = {'Authorization': 'Bearer admin-secret-test'}
r = client.post('/api/v1/models/promote', headers=headers, files=files)
print('status', r.status_code)
print('text', r.text)
