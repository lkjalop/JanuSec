from fastapi.testclient import TestClient
from importlib import import_module
app = import_module('src.api.app').create_app({'mode':'test'})
client = TestClient(app)
r = client.get('/api/v1/labeling/list?page=1&page_size=5')
print('status', r.status_code)
print('text:', r.text)
print('headers:', r.headers)
