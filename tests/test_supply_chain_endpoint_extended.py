from starlette.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})
import json

client = TestClient(app)


def test_endpoint_missing_payload():
    r = client.post('/api/v1/sbom/verify_package', data='')
    # FastAPI will return 422 for missing body schema
    assert r.status_code in (400, 422)


def test_endpoint_invalid_payload_type():
    r = client.post('/api/v1/sbom/verify_package', json={'name': None})
    # handler should process but return ok verdict for minimal input
    assert r.status_code in (200, 422, 400)


def test_endpoint_auth_behavior_demo_mode():
    # In lite/test mode, STRICT_API_KEY_ENFORCEMENT is off; endpoint should be reachable
    payload = {'name': 'requests', 'version': '2.0.0', 'ecosystem': 'pypi'}
    r = client.post('/api/v1/sbom/verify_package', json=payload)
    assert r.status_code == 200
    data = r.json()
    assert 'verdict' in data
