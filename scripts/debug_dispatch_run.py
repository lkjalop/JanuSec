import os
import json
from fastapi.testclient import TestClient
# Set up environment exactly like the test
os.environ['PLATFORM_LITE_INIT'] = '1'
# Import app after env set
from src.api.app import app
# Now set SLACK_WEBHOOK_URL as test does via monkeypatch
os.environ['SLACK_WEBHOOK_URL'] = 'http://127.0.0.1:1234/hook'
client = TestClient(app)
resp = client.post('/api/v1/webhooks/dispatch', json={'service':'slack','text':'hello'})
print('status', resp.status_code)
try:
    print('json', resp.json())
except Exception:
    print('text', resp.text)
