import types
import time
import pytest

from src.integrations.threat_intel_client import ThreatIntelClient


@pytest.mark.asyncio
async def test_misp_since_last_and_pagination(monkeypatch):
    # Ensure stubs are disabled to force real path
    monkeypatch.setenv('THREAT_INTEL_ALLOW_STUBS', '0')
    monkeypatch.setenv('MISP_API_URL', 'https://misp.local')
    monkeypatch.setenv('MISP_API_KEY', 'secret')
    monkeypatch.setenv('MISP_PAGE_LIMIT', '3')
    monkeypatch.setenv('MISP_MAX_PAGES', '5')

    pages_called = []

    class _Attr:
        def __init__(self, t, v):
            self.type = t
            self.value = v

    class PyMISP:  # stub matching import style: from pymisp import PyMISP
        def __init__(self, url, key, *_, **__):
            assert url == 'https://misp.local'
            assert key == 'secret'

        def search(self, controller=None, last=None, limit=None, page=None, pythonify=None):
            pages_called.append((last, limit, page))
            # page 1 returns exactly limit items to trigger pagination
            if page in (None, 1):
                return [
                    _Attr('ip-src', '203.0.113.5'),
                    _Attr('md5', 'a' * 32),
                    _Attr('domain', 'evil.example')
                ][: int(limit or 3)]
            # page 2 returns less than limit causing break
            if page == 2:
                return [_Attr('ip-dst', '198.51.100.9')]
            return []

    fake_mod = types.ModuleType('pymisp')
    fake_mod.PyMISP = PyMISP
    monkeypatch.setitem(__import__('sys').modules, 'pymisp', fake_mod)

    client = ThreatIntelClient()
    # Freeze time: now and 2 hours ago for last_sync
    t0 = 1_700_000_000.0
    client.last_sync['misp'] = t0 - 7200.0
    monkeypatch.setattr('time.time', lambda: t0)

    await client._sync_misp()

    # Check since-last computed as ~2h (string '2h') on first call
    assert pages_called, 'no calls were made to PyMISP.search'
    first_last_arg = pages_called[0][0]
    assert first_last_arg == '2h'

    # Pagination: second page should have been attempted
    pages = [p for (_last, _limit, p) in pages_called]
    assert 2 in pages, f'expected a second page call, got {pages}'

    # IoCs were ingested
    assert '203.0.113.5' in client.ip_set
    assert 'a' * 32 in client.hash_set
    assert 'evil.example' in client.domain_set

