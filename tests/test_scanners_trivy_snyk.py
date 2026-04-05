import os
import pytest
from fastapi.testclient import TestClient

from src.api.server import app
try:
    import respx
except Exception:
    respx = None

class FakeResp:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {'sbom_id':'sbom-1','components':2,'vulns_found':1}
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")
    def json(self):
        return self._json

class FakeAsyncClient:
    def __init__(self):
        self.posts = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False
    async def post(self, url, headers=None, json=None):
        self.posts.append((url, json))
        return FakeResp(200, {'sbom_id': 'sbom-1', 'components': len((json or {}).get('components', [])), 'vulns_found': 1})

@pytest.fixture(autouse=True)
def allow_dev_api_key(monkeypatch):
    monkeypatch.setenv('ALLOW_DEV_API_KEY', '1')

@pytest.mark.asyncio
async def test_trivy_trigger_upload(monkeypatch):
    # Patch httpx AsyncClient used by connectors
    import httpx
    fac = FakeAsyncClient()
    if respx is None:
        monkeypatch.setattr(httpx, 'AsyncClient', lambda timeout=30: fac)
        client = TestClient(app)
        r = client.post('/api/v1/scanners/trivy/trigger', json={'image':'alpine:3.18'})
    else:
        with respx.mock(assert_all_called=False) as rs:
            # generic catch-all for scanner upload endpoints
            rs.post('https://trivy.example/upload').mock(return_value=httpx.Response(200, json={'sbom_id':'sbom-1','components':2,'vulns_found':1}))
            client = TestClient(app)
            r = client.post('/api/v1/scanners/trivy/trigger', json={'image':'alpine:3.18'})
    assert r.status_code == 200
    js = r.json()
    assert js['sbom_result']['sbom_id'] == 'sbom-1'

@pytest.mark.asyncio
async def test_snyk_trigger_upload(monkeypatch):
    import httpx
    fac = FakeAsyncClient()
    if respx is None:
        monkeypatch.setattr(httpx, 'AsyncClient', lambda timeout=30: fac)
        client = TestClient(app)
        r = client.post('/api/v1/scanners/snyk/trigger', json={'project':'sample-app'})
    else:
        with respx.mock(assert_all_called=False) as rs:
            rs.post('https://snyk.example/scan').mock(return_value=httpx.Response(200, json={'sbom_id':'sbom-1','components':2,'vulns_found':1}))
            client = TestClient(app)
            r = client.post('/api/v1/scanners/snyk/trigger', json={'project':'sample-app'})
    assert r.status_code == 200
    js = r.json()
    assert js['sbom_result']['sbom_id'] == 'sbom-1'
