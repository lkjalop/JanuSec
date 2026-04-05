import os, sys
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('DISABLE_DB','1')
API_KEY = os.environ.get('TEST_API_KEY','devkey123')
from src.api.app import app
from fastapi.testclient import TestClient

print('app object id', id(app))
try:
    routes = sorted({getattr(r, 'path', str(r)) for r in app.router.routes})
except Exception:
    routes = sorted({getattr(r, 'path', str(r)) for r in app.routes})
print('routes count', len(routes))
print('iam connectors status present?', '/api/v1/iam/connectors/status' in routes)

client = TestClient(app)
resp = client.get('/api/v1/iam/connectors/status', headers={'x-api-key': API_KEY})
print('GET status', resp.status_code)
try:
    print(resp.json())
except Exception:
    print(resp.text)

# show sys.modules entries for api.app and src.api.app
print('sys.modules api keys:')
for k in sorted([k for k in sys.modules if k.endswith('api.app') or 'api.app' in k]):
    print(k, '->', id(sys.modules[k]))
