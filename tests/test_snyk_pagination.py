import os
import asyncio
import types
import pytest

from src.collectors.scanners.snyk_connector import SnykConnector
try:
    import respx
except Exception:
    respx = None

class DummyResp:
    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {}
    def json(self):
        return self._json
    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

class DummyClient:
    def __init__(self, sequence):
        self._seq = list(sequence)
    async def get(self, url, headers=None):
        # pop from sequence
        if not self._seq:
            return DummyResp(200, {'issues': []})
        return self._seq.pop(0)
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False

@pytest.mark.asyncio
async def test_snyk_pagination_next_field(monkeypatch):
    os.environ['SCANNERS_REAL_MODE'] = '1'
    os.environ['SNYK_TOKEN'] = 't'
    os.environ['SNYK_ORG_ID'] = 'o'
    os.environ['SNYK_PROJECT_ID'] = 'p'
    seq = [
        DummyResp(200, {'issues': [{'pkgName':'a','pkgVersion':'1.0'}], 'next': 'http://next/page'}),
        DummyResp(200, {'issues': [{'pkgName':'b','pkgVersion':'2.0'}]})
    ]
    import httpx
    if respx is None:
        monkeypatch.setattr(httpx, 'AsyncClient', lambda timeout=60: DummyClient(seq))
        conn = SnykConnector()
        out = await conn.run_scan('p')
    else:
        with respx.mock(assert_all_called=False) as rs:
            # generic endpoint placeholder
            rs.get('https://snyk.example/projects/p/issues').mock(side_effect=[httpx.Response(200, json=seq[0]._json), httpx.Response(200, json=seq[1]._json)])
            conn = SnykConnector()
            out = await conn.run_scan('p')
    assert out and 'components' in out
    names = [c['name'] for c in out['components']]
    assert 'a' in names and 'b' in names

@pytest.mark.asyncio
async def test_snyk_pagination_links_header(monkeypatch):
    os.environ['SCANNERS_REAL_MODE'] = '1'
    os.environ['SNYK_TOKEN'] = 't'
    os.environ['SNYK_ORG_ID'] = 'o'
    os.environ['SNYK_PROJECT_ID'] = 'p'
    seq = [
        DummyResp(200, {'issues': [{'pkgName':'a','pkgVersion':'1.0'}]}, headers={'Link':'<http://next/page>; rel="next"'}),
        DummyResp(200, {'issues': [{'pkgName':'b','pkgVersion':'2.0'}]})
    ]
    import httpx
    if respx is None:
        monkeypatch.setattr(httpx, 'AsyncClient', lambda timeout=60: DummyClient(seq))
        conn = SnykConnector()
        out = await conn.run_scan('p')
    else:
        with respx.mock(assert_all_called=False) as rs:
            rs.get('https://snyk.example/projects/p/issues').mock(side_effect=[httpx.Response(200, json=seq[0]._json, headers=seq[0].headers), httpx.Response(200, json=seq[1]._json)])
            conn = SnykConnector()
            out = await conn.run_scan('p')
    assert out and len(out['components']) == 2

@pytest.mark.asyncio
async def test_snyk_retry_on_429(monkeypatch):
    os.environ['SCANNERS_REAL_MODE'] = '1'
    os.environ['SNYK_TOKEN'] = 't'
    os.environ['SNYK_ORG_ID'] = 'o'
    os.environ['SNYK_PROJECT_ID'] = 'p'
    seq = [
        DummyResp(429, {}),
        DummyResp(200, {'issues': [{'pkgName':'a','pkgVersion':'1.0'}]})
    ]
    import httpx
    if respx is None:
        monkeypatch.setattr(httpx, 'AsyncClient', lambda timeout=60: DummyClient(seq))
        conn = SnykConnector()
        out = await conn.run_scan('p')
    else:
        with respx.mock(assert_all_called=False) as rs:
            rs.get('https://snyk.example/projects/p/issues').mock(side_effect=[httpx.Response(429, json={}), httpx.Response(200, json=seq[1]._json)])
            conn = SnykConnector()
            out = await conn.run_scan('p')
    assert out and out['components'][0]['name'] == 'a'
