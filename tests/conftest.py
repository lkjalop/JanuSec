"""Test helpers: seed RBAC roles for CI runs.

Usage:
 - Set TEST_SEED_ROLES_PATH to a JSON file containing { "api_key": ["role1","role2"] }
 - Or set TEST_SEED_ROLES to a JSON string with the same shape.

This hook runs at pytest session start and calls `src.security.rbac.assign_role`.
"""
from __future__ import annotations
import os, json

def pytest_sessionstart(session):
    try:
        from src.security import rbac
    except Exception:
        return
    cfg_path = os.getenv('TEST_SEED_ROLES_PATH')
    cfg_inline = os.getenv('TEST_SEED_ROLES')
    data = None
    try:
        if cfg_path and os.path.exists(cfg_path):
            with open(cfg_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        elif cfg_inline:
            data = json.loads(cfg_inline)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return
    for k, roles in data.items():
        try:
            if isinstance(roles, (list, tuple)):
                for r in roles:
                    try:
                        rbac.assign_role(k, str(r))
                    except Exception:
                        pass
        except Exception:
            continue
import os
import json
# Ensure common test environment variables are available at import-time so
# modules that read them during import see deterministic test keys.
os.environ.setdefault('API_KEYS_JSON', json.dumps([{"key": "testkey123", "scopes": ["*"]}]))
os.environ.setdefault('ADMIN_API_KEY', os.environ.get('ADMIN_API_KEY', 'admin-test'))
os.environ.setdefault('INGEST_API_KEY', os.environ.get('INGEST_API_KEY', 'testkey'))
import pytest


@pytest.fixture(autouse=True)
def ensure_test_env_and_rate_limits(monkeypatch):
    """Autouse fixture that prepares a deterministic test environment.

    - Ensures a canonical API key is present in API_KEYS_JSON so auth middleware
      recognizes test requests.
    - Sets SSE_TEST_MODE so tests that create TestClient after import will see
      test-mode behavior.
    - Attempts to clear rate-limit storages by calling the test helper or
      clearing known module storages. This is best-effort.
    """
    # Provide a permissive test API key with broad scopes to satisfy require_scopes
    # Only set a default if the test module hasn't already configured API_KEYS_JSON.
    if not os.environ.get('API_KEYS_JSON'):
        monkeypatch.setenv('API_KEYS_JSON', json.dumps([{"key": "testkey123", "scopes": ["*"]}]))
    # Enable SSE test mode by default for tests (can be overridden per-test)
    monkeypatch.setenv('SSE_TEST_MODE', '1')
    # Allow tests to opt-into permissive auth behavior by default. Tests that
    # need strict auth can set PERMISSIVE_TEST_AUTH=0 locally.
    monkeypatch.setenv('PERMISSIVE_TEST_AUTH', os.environ.get('PERMISSIVE_TEST_AUTH', '1'))

    # Best-effort: reset any in-memory rate limit storages across modules
    try:
        from tests._helpers import reset_rate_limit_and_headers
        # call with None to just clear storages
        try:
            reset_rate_limit_and_headers(None)
        except Exception:
            # ignore if headers required or other issues
            pass
    except Exception:
        # fallback: try clearing common module storages
        try:
            import sys
            for name, mod in list(sys.modules.items()):
                try:
                    if not name or 'api.app' not in name:
                        continue
                    if getattr(mod, '_RATE_LIMIT_STORAGE', None) is not None:
                        try:
                            getattr(mod, '_RATE_LIMIT_STORAGE').clear()
                        except Exception:
                            pass
                    if getattr(mod, '_TENANT_RATE_STORAGE', None) is not None:
                        try:
                            getattr(mod, '_TENANT_RATE_STORAGE').clear()
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass

    yield
import os
import pytest

# Ensure pytest-asyncio plugin loaded despite PYTEST_DISABLE_PLUGIN_AUTOLOAD to honor @pytest.mark.asyncio
pytest_plugins = ["asyncio"]

# Ensure pytest does not auto-load plugins that pull heavy dependencies during
# collection. Also default to lite-mode for local CI to speed up test imports.
os.environ.setdefault('PYTEST_DISABLE_PLUGIN_AUTOLOAD', '1')
os.environ.setdefault('PLATFORM_LITE_INIT', os.environ.get('PLATFORM_LITE_INIT', '1'))
os.environ.setdefault('SKIP_HEAVY_STARTUP', os.environ.get('SKIP_HEAVY_STARTUP', '1'))
# When running in lite-mode for tests, mount the full set of routes by default so
# functional tests that expect various endpoints are available without performing
# heavy platform initialization. Tests can override this by setting LOAD_FULL_ROUTES=0.
os.environ.setdefault('LOAD_FULL_ROUTES', os.environ.get('LOAD_FULL_ROUTES', '1'))
# Disable tenant rate limiting during most unit tests to avoid 429 failures; integration
# tests can enable it explicitly to validate rate behavior.
os.environ.setdefault('TENANT_RATE_LIMIT_ENABLED', os.environ.get('TENANT_RATE_LIMIT_ENABLED', '0'))
# Disable global IP-based rate limiting during unit tests to avoid tests hitting
# the shared in-memory rate window when the full suite runs in batches.
os.environ.setdefault('RATE_LIMIT_ENABLED', os.environ.get('RATE_LIMIT_ENABLED', '0'))
# By default during unit tests do not enforce strict API key checks. Tests
# that exercise strict auth can set STRICT_API_KEY_ENFORCEMENT=1 explicitly.
os.environ.setdefault('STRICT_API_KEY_ENFORCEMENT', os.environ.get('STRICT_API_KEY_ENFORCEMENT', '0'))


def pytest_collection_modifyitems(config, items):
    """Mark smoke tests to be skipped when running in JANUSEC_TEST_MODE by default.

    To run smoke tests intentionally during CI, set RUN_SMOKE_TESTS=1 in the environment.
    """
    janusec = os.getenv('JANUSEC_TEST_MODE')
    run_smoke = os.getenv('RUN_SMOKE_TESTS')
    if janusec and janusec != '0' and not (run_smoke and run_smoke != '0'):
        skip_marker = pytest.mark.skip(reason='Smoke tests skipped under JANUSEC_TEST_MODE')
        for item in items:
            if 'smoke' in {m.name for m in item.iter_markers()}:
                item.add_marker(skip_marker)
"""Pytest configuration helpers.

Create a default asyncio event loop for the main thread early so tests that
call `asyncio.get_event_loop().run_until_complete(...)` don't see
`RuntimeError: There is no current event loop` on Windows.
"""
import asyncio
import threading

try:
    # On some Python/pytest/plugin orders the event loop policy is set but no
    # loop is installed for the main thread. Create one proactively.
    try:
        _ = asyncio.get_event_loop()
    except RuntimeError:
        if threading.current_thread() is threading.main_thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
except Exception:
    pass


import pytest


@pytest.fixture(autouse=True)
def ensure_event_loop_for_test():
    """Ensure a default event loop exists for the duration of each test.

    Some tests call `asyncio.get_event_loop().run_until_complete(...)` from
    the main thread. If no loop exists due to plugin ordering, provide one.
    """
    try:
        try:
            _ = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except Exception:
        pass
    yield


@pytest.fixture
def loop(event_loop):
    """Compatibility alias fixture for pytest-aiohttp tests expecting 'loop'.

    Some tests declare a dependency on a fixture named 'loop' (pytest-aiohttp
    style). Ensure it is available by aliasing to the standard 'event_loop'
    fixture we already provide.
    """
    return event_loop


@pytest.fixture
def event_loop():
    """Provide a fresh asyncio event loop for tests when the standard
    'event_loop' fixture is not available from plugins. This ensures
    compatibility across different pytest plugin load orders on Windows.
    """
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        try:
            loop.close()
        except Exception:
            pass


@pytest.fixture(autouse=True)
def centralized_test_resets():
    """Autouse fixture that performs centralized, best-effort resets of shared
    runtime singletons before each test to reduce inter-test state leakage.

    This calls safe reset helpers where available and clears common in-memory
    stores such as rate-limit windows, the event queue, and the global hopgraph
    internals. It's intentionally best-effort and will not raise on failure.
    """
    # Reset decision cache and other runtime state helpers
    try:
        from src.api import runtime_state
        try:
            runtime_state.reset_for_tests()
        except Exception:
            pass
        # Clear or replace the in-process EVENT_QUEUE if possible
        try:
            q = getattr(runtime_state, 'EVENT_QUEUE', None)
            if q is not None:
                # Prefer clear() if available
                if hasattr(q, 'clear'):
                    try:
                        q.clear()
                    except Exception:
                        pass
                else:
                    # Attempt to rebind a fresh in-memory EventQueue
                    try:
                        from src.core.event_queue import EventQueue as _InMemEventQueue
                        runtime_state.EVENT_QUEUE = _InMemEventQueue(max_size=int(os.getenv('EVENT_QUEUE_MAX', '2000') or 2000))
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception:
        pass

    # Clear global hopgraph internals if present
    try:
        from src.graph.hopgraph import GLOBAL_HOPGRAPH
        try:
            # Some implementations expose helpers for test resets
            if hasattr(GLOBAL_HOPGRAPH, 'reset_for_tests'):
                try:
                    GLOBAL_HOPGRAPH.reset_for_tests()
                except Exception:
                    pass
            # Best-effort clear of internal containers
            if hasattr(GLOBAL_HOPGRAPH, '_nodes'):
                try:
                    GLOBAL_HOPGRAPH._nodes.clear()
                except Exception:
                    pass
            if hasattr(GLOBAL_HOPGRAPH, '_edges'):
                try:
                    GLOBAL_HOPGRAPH._edges.clear()
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        pass

    # Clear any in-module rate limit storages we can find
    try:
        import sys
        for name, mod in list(sys.modules.items()):
            try:
                if getattr(mod, '_RATE_LIMIT_STORAGE', None) is not None:
                    try:
                        getattr(mod, '_RATE_LIMIT_STORAGE').clear()
                    except Exception:
                        pass
                if getattr(mod, '_TENANT_RATE_STORAGE', None) is not None:
                    try:
                        getattr(mod, '_TENANT_RATE_STORAGE').clear()
                    except Exception:
                        pass
                # If module exposes a DECISION_CACHE, align it to the canonical runtime DECISION_CACHE
                try:
                    if getattr(mod, 'DECISION_CACHE', None) is not None:
                        try:
                            import importlib
                            rt = importlib.import_module('src.api.runtime_state')
                            setattr(mod, 'DECISION_CACHE', getattr(rt, 'DECISION_CACHE'))
                        except Exception:
                            pass
                except Exception:
                    pass
                # Call a module-level reset helper for rate limits if available
                try:
                    if hasattr(mod, 'reset_rate_limit_for_tests') and callable(getattr(mod, 'reset_rate_limit_for_tests')):
                        try:
                            mod.reset_rate_limit_for_tests()
                        except Exception:
                            pass
                except Exception:
                    pass
            except Exception:
                pass
    except Exception:
        pass

    yield

import time
import pytest

@pytest.fixture(scope='session')
def fixed_start_ts():
    """Provide a deterministic start timestamp for synthetic beacon series.

    Using a fixed epoch base keeps interval computations stable across test runs
    and enables future multi-scale beacon period estimation tests to assert on
    exact expected period values without flakiness.
    """
    # Use a recent but constant epoch anchor; any fixed float works.
    return 1_700_000_000.0
import os
import sys
import pathlib
import pytest


def pytest_configure(config):
    # Ensure src is on sys.path for tests run from workspace root
    root = pathlib.Path(__file__).resolve().parents[1]
    src = root / 'src'
    sp = str(src)
    if sp not in sys.path:
        sys.path.insert(0, sp)
    # Normalize common module aliases so tests that reload modules using
    # either 'api.*' or 'src.api.*' see the same module object. Some tests
    # call importlib.reload(...) on a module whose __spec__.name may be the
    # short package name 'api.app' while the import used elsewhere was
    # 'src.api.app', which can lead to ImportError: module api.app not in
    # sys.modules. Add canonical aliases for the common module names used in
    # this codebase to avoid duplicate module objects.
    try:
        import sys as _sys
        # Map src.api.app -> api.app when only the former is present
        if 'src.api.app' in _sys.modules and 'api.app' not in _sys.modules:
            _sys.modules['api.app'] = _sys.modules['src.api.app']
        # Map src.api.runtime_state -> api.runtime_state
        if 'src.api.runtime_state' in _sys.modules and 'api.runtime_state' not in _sys.modules:
            _sys.modules['api.runtime_state'] = _sys.modules['src.api.runtime_state']
        # Also ensure the reverse mapping in case tests import via short name first
        if 'api.app' in _sys.modules and 'src.api.app' not in _sys.modules:
            _sys.modules['src.api.app'] = _sys.modules['api.app']
        if 'api.runtime_state' in _sys.modules and 'src.api.runtime_state' not in _sys.modules:
            _sys.modules['src.api.runtime_state'] = _sys.modules['api.runtime_state']
        # Also ensure server module aliasing so tests that patch 'src.api.server'
        # affect the module object used by the running app (which may be
        # imported as 'api.server').
        if 'src.api.server' in _sys.modules and 'api.server' not in _sys.modules:
            _sys.modules['api.server'] = _sys.modules['src.api.server']
        if 'api.server' in _sys.modules and 'src.api.server' not in _sys.modules:
            _sys.modules['src.api.server'] = _sys.modules['api.server']
        # Map repositories.audit_repo aliases used by some tests
        if 'src.repositories.audit_repo' in _sys.modules and 'repositories.audit_repo' not in _sys.modules:
            _sys.modules['repositories.audit_repo'] = _sys.modules['src.repositories.audit_repo']
        if 'repositories.audit_repo' in _sys.modules and 'src.repositories.audit_repo' not in _sys.modules:
            _sys.modules['src.repositories.audit_repo'] = _sys.modules['repositories.audit_repo']
        # Also ensure integration modules are accessible under both src.integrations.*
        # and integrations.* to avoid reload/monkeypatch mismatches in tests.
        try:
            for name in list(_sys.modules.keys()):
                if name.startswith('src.integrations.'):
                    short = name[len('src.'):]
                    if short not in _sys.modules:
                        _sys.modules[short] = _sys.modules[name]
                if name.startswith('integrations.'):
                    long = 'src.' + name
                    if long not in _sys.modules:
                        _sys.modules[long] = _sys.modules[name]
        except Exception:
            pass
        # Also normalize repositories.* aliases to ensure in-memory fallbacks
        # (e.g. hunt_lane_events_repo._INMEM_BUFFER) are the same module object
        # across tests and API imports.
        try:
            for name in list(_sys.modules.keys()):
                if name.startswith('src.repositories.'):
                    short = name[len('src.') :]
                    if short not in _sys.modules:
                        _sys.modules[short] = _sys.modules[name]
                if name.startswith('repositories.'):
                    long = 'src.' + name
                    if long not in _sys.modules:
                        _sys.modules[long] = _sys.modules[name]
        except Exception:
            pass
    except Exception:
        pass


def pytest_sessionstart(session):
    # Speed up background loops & skip DB where code supports test flags
    os.environ.setdefault('FAST_TEST_MODE', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    # Wrap importlib.reload with a test-safe variant that ensures the module
    # object is present in sys.modules under its canonical spec/name before
    # calling the real reload. Some tests import modules under different
    # package names (e.g. 'api.app' vs 'src.api.app') which can result in
    # ImportError: module X not in sys.modules when importlib.reload is
    # invoked. This wrapper is test-only and avoids modifying production
    # behavior.
    try:
        # Prefer to use the reusable helper implemented under tests.utils.safe_reload
        try:
            from tests.utils import safe_reload as _safe_mod
            # Wrap importlib.reload to call our safe_reload for test safety
            import importlib as _importlib
            _orig_reload = _importlib.reload
            def _wrap_reload(m):
                try:
                    return _safe_mod.safe_reload(m) or _orig_reload(m)
                except Exception:
                    return _orig_reload(m)
            _importlib.reload = _wrap_reload
        except Exception:
            # Fallback to original safe-reload embedding if helper not available
            import importlib as _importlib
            import sys as _sys
            _real_reload = _importlib.reload
            def _safe_reload(module):
                try:
                    name = getattr(module, '__spec__', None) and getattr(module.__spec__, 'name', None) or getattr(module, '__name__', None)
                    if name:
                        if _sys.modules.get(name) is not module:
                            _sys.modules[name] = module
                    return _real_reload(module)
                except Exception:
                    return _real_reload(module)
            _importlib.reload = _safe_reload
    except Exception:
        pass

    # Test-time DB migrations: create lightweight sqlite tables used by tests
    # Some tests rely on sqlite tables such as `webhook_batches`, `outbox`,
    # and `hunt_lane_events` existing. During test runs we may set DISABLE_DB
    # but still use the sqlite files for persistence; proactively ensure the
    # tables exist to avoid falling back to in-memory stores and flakey tests.
    try:
        import sqlite3
        db_paths = []
        tip = os.getenv('THREAT_INTEL_DB_PATH')
        if tip:
            db_paths.append(tip)
        ob = os.getenv('OUTBOX_SQLITE_PATH')
        if ob:
            db_paths.append(ob)
        # Normalize to unique
        db_paths = list(dict.fromkeys([str(p) for p in db_paths if p]))
        for dbp in db_paths:
            try:
                conn = sqlite3.connect(dbp)
                cur = conn.cursor()
                # webhook_batches used by cert_checks
                try:
                    cur.execute('CREATE TABLE IF NOT EXISTS webhook_batches(id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT, attempts INTEGER, last_error TEXT, created INTEGER)')
                except Exception:
                    pass
                # outbox schema (simple subset) used by outbox_repo_sqlite
                try:
                    cur.execute('''CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, connector TEXT, tenant_id TEXT, event_id TEXT, payload_json TEXT, attempts INTEGER, next_retry INTEGER, created_at INTEGER, updated_at INTEGER, last_error TEXT)''')
                except Exception:
                    pass
                # hunt_lane_events simple schema used by hunt lane repo when DB is present
                try:
                    cur.execute('''CREATE TABLE IF NOT EXISTS hunt_lane_events (created_at REAL, tenant_id TEXT, event_id TEXT, lane TEXT, factors TEXT, latency_ms REAL)''')
                except Exception:
                    pass
                # incidents for some integration tests (lightweight variant)
                try:
                    cur.execute('''CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, artifact_id TEXT, title TEXT, severity TEXT, status TEXT, summary TEXT, tags TEXT, metadata TEXT, created_at REAL, tenant_id TEXT)''')
                except Exception:
                    pass
                conn.commit(); conn.close()
            except Exception:
                pass
    except Exception:
        pass


import time


class HTTPRetry:
    def __init__(self, client, retries=3, backoff=0.5):
        self.client = client
        self.retries = retries
        self.backoff = backoff

    def request(self, method, url, **kwargs):
        last = None
        for i in range(self.retries):
            try:
                r = self.client.request(method, url, **kwargs)
                if getattr(r, 'status_code', 0) < 500:
                    return r
                last = r
            except Exception as e:
                last = e
            time.sleep(self.backoff * (2 ** i))
        return last


@pytest.fixture
def http_retry():
    return HTTPRetry


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # attach result to item for dump_on_failure hook
    outcome = yield
    rep = outcome.get_result()
    setattr(item, 'rep_' + rep.when, rep)


@pytest.fixture
def dump_on_failure(request):
    records = []
    yield records
    # If the test failed, print request/response records
    if getattr(request.node, 'rep_call', None) and request.node.rep_call.failed:
        import logging
        _log = logging.getLogger('tests.dump_on_failure')
        for rec in records:
            try:
                _log.debug('\n--- HTTP RECORD ---')
                _log.debug('%s', rec)
            except Exception:
                pass


@pytest.fixture(autouse=True)
def reset_in_memory_services():
    # Clear in-memory baseline store between tests to prevent ordering flakiness
    try:
        from core.baseline_service import BASELINES
        try:
            BASELINES._store.clear()
        except Exception:
            pass
    except Exception:
        pass


@pytest.fixture(autouse=True)
def normalize_integration_module_aliases():
    """Ensure that modules under `src.integrations.*` and `integrations.*`
    refer to the same module object in sys.modules so pytest monkeypatching a
    module attribute affects the object used by the running code.

    This runs before each test to catch modules imported during test setup as
    well as those already loaded.
    """
    try:
        import sys as _sys
        names = list(_sys.modules.keys())
        for name in names:
            try:
                if name.startswith('src.integrations.'):
                    short = name[len('src.') :]
                    if short not in _sys.modules:
                        _sys.modules[short] = _sys.modules[name]
                if name.startswith('integrations.'):
                    long = 'src.' + name
                    if long not in _sys.modules:
                        _sys.modules[long] = _sys.modules[name]
                # also ensure repository aliases are normalized
                if name.startswith('src.repositories.'):
                    short = name[len('src.') :]
                    if short not in _sys.modules:
                        _sys.modules[short] = _sys.modules[name]
                if name.startswith('repositories.'):
                    long = 'src.' + name
                    if long not in _sys.modules:
                        _sys.modules[long] = _sys.modules[name]
            except Exception:
                pass
    except Exception:
        pass
    yield
    # Also clear runtime decision cache to avoid cross-test leakage
    try:
        from src.api import runtime_state
        try:
            runtime_state.reset_for_tests()
        except Exception:
            pass
    except Exception:
        pass
    # Ensure file batch caches are cleared on the canonical app runtime
    try:
        from src.api.app import app as _app
        from src.api.runtime_state import get_server_runtime_state, get_file_hash_factors, get_file_batch_analysis
        _rt = get_server_runtime_state(_app)
        try:
            get_file_hash_factors(_rt).clear()
        except Exception:
            pass
        try:
            get_file_batch_analysis(_rt).clear()
        except Exception:
            pass
    except Exception:
        pass


# Provide aiohttp_client fixture compatibility for tests expecting pytest-aiohttp
try:
    from aiohttp.test_utils import TestClient as AiohttpTestClient, TestServer as AiohttpTestServer  # type: ignore
    _HAS_AIOHTTP = True
except Exception:
    _HAS_AIOHTTP = False

from starlette.testclient import TestClient as StarletteTestClient


@pytest.fixture
async def aiohttp_client():
    """Compatibility fixture named `aiohttp_client(app)` used by some tests.

    If aiohttp is available, yield a factory that returns an aiohttp TestClient.
    Otherwise yield an async factory that returns a lightweight wrapper around
    Starlette's TestClient providing async get/post and an async .json() on
    responses to mimic aiohttp semantics.
    """
    # Use Starlette TestClient wrapper for FastAPI apps to avoid passing a
    # FastAPI app to aiohttp TestServer (which raises TypeError). Some tests
    # expect an `aiohttp_client` fixture but only need async get/post helpers.
    import asyncio

    class _RespWrapper:
        def __init__(self, resp):
            self._resp = resp
            # aiohttp uses `.status` attribute
            self.status = getattr(resp, 'status_code', getattr(resp, 'status', None))

        async def json(self):
            # Run sync .json() in thread to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._resp.json)

        @property
        def status_code(self):
            return getattr(self._resp, 'status_code', None)

        @property
        def text(self):
            return getattr(self._resp, 'text', None)

    class _AsyncStarletteClient:
        def __init__(self, app):
            self._client = StarletteTestClient(app)

        async def get(self, path, **kwargs):
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, lambda: self._client.get(path, **kwargs))
            return _RespWrapper(resp)

        async def post(self, path, **kwargs):
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, lambda: self._client.post(path, **kwargs))
            return _RespWrapper(resp)

    async def _make(app):
        return _AsyncStarletteClient(app)
    yield _make

# Deterministic time fixture for beacon-related tests
@pytest.fixture
def fixed_time(monkeypatch):
    import time as _t
    base = 1700000000.0
    monkeypatch.setattr(_t, 'time', lambda: base)
    yield base
    # cleanup baseline store once
    try:
        from core.baseline_service import BASELINES
        try:
            BASELINES._store.clear()
        except Exception:
            pass
    except Exception:
        pass

# Autouse: reload rules engine if FEATURE_FLAGS changed during test (correlation rule activation)
import os as _os
import pytest as _pytest
@_pytest.fixture(autouse=True)
def _reload_rules_on_feature_flags():
    prev = _os.getenv('FEATURE_FLAGS')
    yield
    cur = _os.getenv('FEATURE_FLAGS')
    if cur != prev:
        try:
            from src.api.runtime_state import reload_rules_for_tests
            reload_rules_for_tests()
        except Exception:
            pass
