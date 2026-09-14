import os
import json
import pytest

# Fast-path for unit tests: disable pytest auto plugin autoload and enable
# lite init so imports are lightweight. Explicitly load asyncio plugin via
# pytest_plugins so async coroutines run without requiring extra CLI flags.
os.environ.setdefault('PYTEST_DISABLE_PLUGIN_AUTOLOAD', '1')
os.environ.setdefault('PLATFORM_LITE_INIT', '1')
pytest_plugins = ["asyncio"]


@pytest.mark.asyncio
async def test_admin_flags_toggle(tmp_path, monkeypatch):
    # point FLAGS_FILE to a temp location
    flags_file = tmp_path / 'flags.json'
    monkeypatch.setenv('FLAGS_FILE', str(flags_file))
    # allow admin without token for local by bypassing check (set env used by check_admin_token)
    from httpx import AsyncClient
    from src.api.app import app
    # Ensure endpoints import (don't reload; reload is expensive and not
    # necessary now that server uses lite-mode guards). A plain import is
    # sufficient to access admin endpoints during tests.
    from src.api import server as _server
    async with AsyncClient(app=app, base_url='http://test') as ac:
        # monkeypatch auth to no-op for tests
        async def _noop(request):
            return None
        monkeypatch.setattr(_server, 'check_admin_token_async', _noop)
        # initial list
        r = await ac.get('/api/v1/admin/flags')
        assert r.status_code == 200
        data = r.json()
        assert 'effective' in data
        # set a flag
        payload = {'name': 'FEATURE_SLO_ENFORCE_DISPLAY', 'value': True, 'persist': True}
        r2 = await ac.post('/api/v1/admin/flags/set', json=payload)
        assert r2.status_code == 200
        # verify value shows as true
        r3 = await ac.get('/api/v1/admin/flags')
        eff = r3.json()['effective']
        assert eff.get('FEATURE_SLO_ENFORCE_DISPLAY') is True
        # verify persisted file
        assert flags_file.exists()
        j = json.loads(flags_file.read_text())
        assert j.get('FEATURE_SLO_ENFORCE_DISPLAY') is True
        # clear override
        r4 = await ac.delete('/api/v1/admin/flags/FEATURE_SLO_ENFORCE_DISPLAY')
        assert r4.status_code == 200
        # should still return a boolean (from env/defaults)
        r5 = await ac.get('/api/v1/admin/flags')
        eff2 = r5.json()['effective']
        assert 'FEATURE_SLO_ENFORCE_DISPLAY' in eff2
