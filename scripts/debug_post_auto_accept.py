import os, json, sys
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
# match test env
os.environ['API_KEYS_JSON'] = json.dumps([{'key': 'k3', 'scopes': ['factors.search', 'recalibrator.admin']}])
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
# allow jwt path
os.environ['JWT_SECRET'] = 'test-jwt-secret'
from fastapi.testclient import TestClient
from src.api.server import app
client = TestClient(app)
# try API key
resp = client.post('/api/v1/risk/calibration/auto_accept', headers={'x-api-key':'k3'})
print('status', resp.status_code)
try:
    print(resp.json())
except Exception:
    print(resp.text)
# try bearer
import jwt
token = jwt.encode({'sub':'t','scopes':['factors.search']}, os.environ['JWT_SECRET'], algorithm='HS256')
resp2 = client.post('/api/v1/risk/calibration/auto_accept', headers={'Authorization': f'Bearer {token}'})
print('status2', resp2.status_code)
try:
    print(resp2.json())
except Exception:
    print(resp2.text)
