import os
import json
import tempfile
from fastapi.testclient import TestClient
from fastapi import FastAPI

# Ensure lite/test env to avoid heavy init
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('DISABLE_DB','1')
os.environ.setdefault('ALLOW_INSECURE_FALLBACK','1')

os.environ.setdefault('CONNECTORS_POLICY_PATH', os.path.join(tempfile.gettempdir(), 'connectors_policies_test.json'))
os.environ.setdefault('CONNECTORS_SECRETS_PATH', os.path.join(tempfile.gettempdir(), 'connectors_secrets_test.json'))
from src.api.connector_admin_endpoints import router as admin_router

app = FastAPI()
app.include_router(admin_router)
client = TestClient(app)

API_KEY = os.getenv('DEV_DEMO_API_KEY','devkey123')
HDRS = {'x-api-key': API_KEY}

def test_policies_crud():
    pol_path = os.environ['CONNECTORS_POLICY_PATH']
    try:
        if os.path.exists(pol_path):
            os.remove(pol_path)
    except Exception:
        pass

    # List initially empty
    r = client.get('/api/v1/admin/connectors/policies', headers=HDRS)
    assert r.status_code == 200
    body = r.json()
    assert body['count'] == 0

    # Update a policy
    payload = {
        'enabled': True,
        'rate_limit': {'rate_per_second': 3.0, 'burst': 6.0},
        'cost_cap_usd': 25.0,
        'allow_hosts': ['api.example.com','.slack.com']
    }
    r = client.post('/api/v1/admin/connectors/policies/purview', headers=HDRS, json=payload)
    assert r.status_code == 200

    # Fetch specific policy
    r = client.get('/api/v1/admin/connectors/policies/purview', headers=HDRS)
    assert r.status_code == 200
    body = r.json()
    assert body['name'] == 'purview'
    assert body['enabled'] is True
    assert body['policy']['rate_limit']['rate_per_second'] == 3.0

    # Verify file persistence
    assert os.path.exists(pol_path)
    with open(pol_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert 'purview' in data


def test_secrets_store():
    sec_path = os.environ['CONNECTORS_SECRETS_PATH']
    try:
        if os.path.exists(sec_path):
            os.remove(sec_path)
    except Exception:
        pass

    # Set secrets for a connector
    r = client.post('/api/v1/admin/connectors/secrets/purview', headers=HDRS, json={'values': {'api_key':'abc123','tenant':'t1'}})
    assert r.status_code == 200
    body = r.json()
    assert body['saved'] is True
    assert body['name'] == 'purview'

    # Verify redacted GET
    r = client.get('/api/v1/admin/connectors/secrets/purview', headers=HDRS)
    assert r.status_code == 200
    body = r.json()
    assert body['name'] == 'purview'
    assert body['secrets']['api_key'] == '***'
    assert body['secrets']['tenant'] == '***'

    # File persisted
    assert os.path.exists(sec_path)
    with open(sec_path, 'r', encoding='utf-8') as f:
        raw = json.load(f)
    # Keys exist in file; values may be encrypted or plain (fallback enabled)
    assert 'purview' in raw
    assert set(raw['purview'].keys()) == {'api_key','tenant'}
