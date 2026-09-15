"""Small test helpers used across pytest files."""
from typing import Dict


def reset_rate_limit_and_headers(client_ip: str = '127.0.0.1') -> Dict[str, str]:
    """Reset in-memory rate limiter windows (best-effort) and return a
    deterministic headers dict containing an X-Forwarded-For to ensure
    middleware keys are stable in tests.
    """
    try:
        import src.api.app as _app
        if hasattr(_app, 'reset_rate_limit_for_tests'):
            _app.reset_rate_limit_for_tests()
        # Also clear direct storage if present
        try:
            _app._RATE_LIMIT_STORAGE.clear()
        except Exception:
            pass
        try:
            _app._TENANT_RATE_STORAGE.clear()
        except Exception:
            pass
    except Exception:
        pass
    # Additionally, clear any aliased module instances that might hold their own
    # rate-limit storages (e.g., 'api.app' vs 'src.api.app') so batch runs are
    # deterministic regardless of import aliasing.
    try:
        import sys as _sys
        for name, mod in list(_sys.modules.items()):
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
    api_key = None
    try:
        import os
        api_key = os.getenv('X_API_KEY') or os.getenv('JANUSEC_API_KEY') or os.getenv('INGEST_API_KEY') or os.getenv('API_KEY')
        # If tests set a dedicated ingest/admin key (e.g. INGEST_API_KEY) ensure
        # the global API_KEYS_JSON environment includes it so the strict global
        # API key middleware recognizes the key during request-time auth checks.
        try:
            import json
            existing = os.getenv('API_KEYS_JSON', '')
            entries = []
            if existing:
                try:
                    arr = json.loads(existing)
                    if isinstance(arr, list):
                        entries = arr
                except Exception:
                    entries = []
            # If api_key is set and not already present in API_KEYS_JSON, add a permissive entry
            if api_key:
                found = False
                for e in list(entries):
                    try:
                        if isinstance(e, dict) and e.get('key') == api_key:
                            found = True
                            break
                    except Exception:
                        pass
                if not found:
                    # Add with broad scopes used by tests
                    entries.append({'key': api_key, 'scopes': ['feedback.write','factors.search','models.promote','models.alias','nlp.query']})
                    try:
                        os.environ['API_KEYS_JSON'] = json.dumps(entries)
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception:
        api_key = None
    if not api_key:
        api_key = 'janusec-test-key'
    return {'X-Forwarded-For': client_ip, 'X-API-Key': api_key}


def default_test_headers(client_ip: str = '127.0.0.1') -> Dict[str, str]:
    """Return deterministic headers used by tests: X-Forwarded-For + X-API-Key."""
    return reset_rate_limit_and_headers(client_ip)


def admin_test_headers(client, admin_token: str = 'testtoken', client_ip: str = '127.0.0.1') -> Dict[str, str]:
    """Set CSRF cookie on the provided TestClient and return headers for admin calls.

    This helper performs the double-submit CSRF setup expected by the CSRFMiddleware:
    - sets the CSRF cookie (name determined by src.api.csrf.CSRF_COOKIE)
    - returns headers including X-Forwarded-For, X-API-Key, X-Admin-Token and the CSRF header

    Usage:
        hdrs = admin_test_headers(client)
        resp = client.post('/api/v1/admin/some', headers=hdrs, json={...})
    """
    # ensure deterministic base headers and reset rate limits
    hdrs = reset_rate_limit_and_headers(client_ip)
    # admin token header used by admin endpoints
    hdrs.update({'X-Admin-Token': admin_token})
    # CSRF header name lives in src.api.csrf.CSRF_HEADER
    try:
        from src.api.csrf import CSRF_COOKIE, CSRF_HEADER
        # set cookie on the TestClient (requests-style client exposes .cookies)
        try:
            client.cookies.set(CSRF_COOKIE, 'csrfval')
        except Exception:
            # some test clients may expose a different API; ignore failures
            pass
        hdrs[CSRF_HEADER] = 'csrfval'
    except Exception:
        # fallback names
        try:
            client.cookies.set('janusec_csrf', 'csrfval')
        except Exception:
            pass
        hdrs['x-csrf-token'] = 'csrfval'
    return hdrs
