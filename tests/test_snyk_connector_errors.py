import os
import pytest

from src.collectors.scanners.snyk_connector import SnykConnector

class DummyResponse:
    def __init__(self, status_code: int, url: str = 'https://api.snyk.io/test'):
        import httpx
        self.status_code = status_code
        self._req = httpx.Request('GET', url)
    def json(self):
        return {}
    def raise_for_status(self):
        import httpx
        if 400 <= self.status_code:
            raise httpx.HTTPStatusError('error', request=self._req, response=self)

class DummyClient429:
    def __init__(self, *args, **kwargs):
        self.calls = 0
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False
    async def get(self, url, headers=None):
        self.calls += 1
        return DummyResponse(429, url)

class DummyClient500:
    def __init__(self, *args, **kwargs):
        self.calls = 0
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False
    async def get(self, url, headers=None):
        self.calls += 1
        return DummyResponse(500, url)

class DummyClientTimeout:
    def __init__(self, *args, **kwargs):
        self.calls = 0
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False
    async def get(self, url, headers=None):
        self.calls += 1
        import httpx
        raise httpx.ReadTimeout('timeout', request=None)

@pytest.mark.anyio
@pytest.mark.parametrize('client_cls, expected_status, expect_none', [
    (DummyClient429, 429, False),
    (DummyClient500, 500, False),
    (DummyClientTimeout, None, True),
])
async def test_snyk_connector_error_modes(monkeypatch, client_cls, expected_status, expect_none):
    # Force real mode
    monkeypatch.setenv('SCANNERS_REAL_MODE', '1')
    # Patch AsyncClient to our dummy
    import httpx
    monkeypatch.setattr(httpx, 'AsyncClient', client_cls)
    conn = SnykConnector()
    res = await conn.run_scan('dummy-project')
    assert 'components' in res
    assert isinstance(res['components'], list)
    # Expect errors structured when no components retrieved
    assert 'errors' in res
    assert len(res['errors']) >= 1
    err = res['errors'][0]
    if expect_none:
        assert err['status_code'] is None
        assert err['retries'] >= 3
    else:
        assert err['status_code'] == expected_status
        assert err['retries'] >= (5 if expected_status == 429 else 3)
    # meta present
    assert 'meta' in res and 'pages' in res['meta']
