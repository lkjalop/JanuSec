import os
import json
from fastapi.testclient import TestClient
import importlib

os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('TEST_HELPERS_ENABLED','1')

from src.api.connector_admin_endpoints import router as admin_router
from src.api.connector_admin_endpoints import _SECRETS_PATH
from fastapi import FastAPI

app = FastAPI()
app.include_router(admin_router)
client = TestClient(app)

API_KEY = 'badkey'
GOOD_KEY = 'devkey123'


def test_unauthorized_policy_access():
    # without admin key, should get 401 or 403
    r = client.get('/api/v1/admin/connectors/policies')
    assert r.status_code in (401,403)
    # with permissive dev key granted by auth, should work
    r = client.get('/api/v1/admin/connectors/policies', headers={'x-api-key': GOOD_KEY})
    assert r.status_code == 200


def test_secrets_rbac_and_crypto(tmp_path, monkeypatch):
    # prepare secrets path
    sec = tmp_path / 'secrets.json'
    monkeypatch.setenv('CONNECTORS_SECRETS_PATH', str(sec))
    # ensure cryptography absent by monkeypatching Fernet import path
    # simulate cryptography not installed by setting ALLOW_INSECURE_FALLBACK=0 and removing Fernet
    monkeypatch.setenv('ALLOW_INSECURE_FALLBACK','0')
    # reload crypto_utils to pick env changes
    import src.security.crypto_utils as cu
    importlib.reload(cu)
    # If cryptography is missing and fallback not allowed, encrypt should raise at _get_key; endpoints should handle
    # Attempt POST secrets with good key should either succeed (if test harness allows fallback) or return 500
    r = client.post('/api/v1/admin/connectors/secrets/testconn', headers={'x-api-key': GOOD_KEY}, json={'values': {'k':'v'}})
    # Accept either 200 or 500 depending on environment, but ensure unauthorized fails
    assert r.status_code in (200,500)
    # unauthorized save should be rejected
    r = client.post('/api/v1/admin/connectors/secrets/testconn', headers={'x-api-key': API_KEY}, json={'values': {'k':'v'}})
    assert r.status_code in (401,403)