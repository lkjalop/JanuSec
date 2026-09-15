import os, json
from fastapi.testclient import TestClient
import importlib
# mimic test: set security.auth cached keys
try:
    import security.auth as _sa
    _sa._API_KEYS = {'k3': ['factors.search']}
except Exception:
    pass
from src.api.server import app
client = TestClient(app)
resp = client.post('/api/v1/risk/calibration/auto_accept', headers={'x-api-key':'k3'})
print('status', resp.status_code)
print('body', resp.text)
