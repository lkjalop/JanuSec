import os
import json
import traceback
from fastapi.testclient import TestClient

# Ensure API key env is present like tests
os.environ['API_KEYS_JSON'] = json.dumps([{'key': 'k3', 'scopes': ['factors.search', 'recalibrator.admin']}])

try:
    # set JWT secret like the test
    os.environ['JWT_SECRET'] = 'test-jwt-secret'
    import jwt
    has_jwt = True
except Exception as e:
    print('pyjwt import failed:', e)
    has_jwt = False

from src.api.server import app
client = TestClient(app)

# Build auth header
if has_jwt:
    try:
        token = jwt.encode({'sub':'t','scopes':['factors.search']}, os.environ['JWT_SECRET'], algorithm='HS256')
        auth_hdr = {'Authorization': f'Bearer {token}'}
    except Exception as e:
        print('jwt.encode error:', e)
        auth_hdr = {'x-api-key':'k3'}
else:
    auth_hdr = {'x-api-key':'k3'}

print('Using headers:', auth_hdr)

resp = client.post('/api/v1/risk/calibration/auto_accept', headers=auth_hdr)
print('status_code', resp.status_code)
try:
    print('json:', resp.json())
except Exception:
    print('text:', resp.text)

# If 401, attempt to call auth dependency directly to see error
if resp.status_code == 401:
    try:
        from security.auth import auth_dependency
        # emulate header values
        x_api_key = auth_hdr.get('x-api-key')
        auth = auth_hdr.get('Authorization')
        # call sync via asyncio
        import asyncio
        out = asyncio.run(auth_dependency(x_api_key, auth, ['factors.search']))
        print('auth_dependency result:', out.subject, out.scopes)
    except Exception:
        print('auth_dependency invocation failed:')
        traceback.print_exc()
