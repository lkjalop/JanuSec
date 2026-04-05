import os, sys
sys.path.insert(0, '.')
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
from fastapi.testclient import TestClient
from src.api.server import app
client=TestClient(app)
print('POST /api/v1/admin/ingest/thresholds')
r = client.post('/api/v1/admin/ingest/thresholds', json={'items': {'default': 2}})
print('status', r.status_code)
try:
    print('body', r.json())
except Exception:
    print('body raw', r.text)

print('\nGET /api/v1/admin/ingest/status')
r2 = client.get('/api/v1/admin/ingest/status')
print('status', r2.status_code)
try:
    print('body', r2.json())
except Exception:
    print('body raw', r2.text)

print('\nPOST /api/v1/admin/ingest/reset')
r3 = client.post('/api/v1/admin/ingest/reset', json={'tenant_id': 'default'})
print('status', r3.status_code)
try:
    print('body', r3.json())
except Exception:
    print('body raw', r3.text)
