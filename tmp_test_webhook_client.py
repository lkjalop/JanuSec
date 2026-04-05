import os, json
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('DISABLE_DB','1')
from src.api.app import create_app
app = create_app({'mode':'test'})
from fastapi.testclient import TestClient
client = TestClient(app)
print('app id', id(app))
print('routes:', sorted({getattr(r,'path',None) for r in app.router.routes if getattr(r,'path',None) and r.path.startswith('/api/v1/iam')}))
payload = {"data": {"events": [{"eventType": "user.session.start","published": "2025-01-01T00:00:00Z","actor": {"alternateId": "bob@example.com"},"client": {"ipAddress": "1.2.3.4"}}]}}
resp = client.post('/api/v1/iam/okta/webhook', headers={'x-api-key': os.environ.get('TEST_API_KEY','devkey123')}, json=payload)
print('status', resp.status_code)
try:
    print('json', resp.json())
except Exception:
    print('text', resp.text)
