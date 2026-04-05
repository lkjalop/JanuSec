import os
import time

import pytest


pytestmark = pytest.mark.smoke


def base_url() -> str:
    return os.getenv("JANUSEC_BASE", "http://localhost:8080")


def _get_client():
    """Return a client-like object. If JANUSEC_BASE is the default localhost
    value, prefer to use the in-process TestClient against the application's
    FastAPI app so tests don't depend on an external process running.
    """
    base = base_url()
    if 'JANUSEC_BASE' in os.environ:
        # Explicit base provided by environment; use real httpx client
        import httpx
        return httpx.Client(timeout=10.0)
    # No explicit base - use internal TestClient to hit the app directly
    try:
        from fastapi.testclient import TestClient
        import importlib
        appmod = importlib.import_module('src.api.app')
        return TestClient(appmod.app)
    except Exception:
        # Fallback to httpx client if TestClient or app import fails
        import httpx
        return httpx.Client(timeout=10.0)


def _client_get(c, path: str):
    # path should start with '/'
    try:
        from fastapi.testclient import TestClient
        if isinstance(c, TestClient):
            return c.get(path)
    except Exception:
        pass
    # httpx client: requires full URL
    import httpx
    b = base_url()
    return c.get(f"{b}{path}")


def _client_post(c, path: str, json=None):
    try:
        from fastapi.testclient import TestClient
        if isinstance(c, TestClient):
            return c.post(path, json=json)
    except Exception:
        pass
    import httpx
    b = base_url()
    return c.post(f"{b}{path}", json=json)


def _lazy_httpx():
    try:
        import httpx  # type: ignore
        return httpx
    except Exception as e:
        pytest.skip(f"httpx not installed: {e}")


def test_health_and_formats():
    httpx = _lazy_httpx()
    b = base_url()

    c = _get_client()
    try:
        r = _client_get(c, '/api/v1/health')
        assert r.status_code == 200
        j = r.json()
        assert isinstance(j, dict)
        assert j.get("status") == "ok"

        r2 = _client_get(c, '/api/v1/upload/supported-formats')
        assert r2.status_code == 200
        j2 = r2.json()
        assert isinstance(j2, dict)
        assert "formats" in j2
    finally:
        try:
            c.close()
        except Exception:
            pass


def test_log_batch_happy_path():
    httpx = _lazy_httpx()
    b = base_url()
    events = [
        {
            "id": f"smoke-{int(time.time()*1000)}",
            "host": "pytest-host",
            "dns_rcode": 0,
            "details": {"ip": "8.8.8.8"},
        }
    ]
    payload = {"events": events, "classify": False, "send_alerts": False, "include_rules": False}
    c = _get_client()
    try:
        r = _client_post(c, '/api/v1/endpoints/log_batch', json=payload)
        assert r.status_code == 200
        j = r.json()
        assert j.get("accepted") == len(events)
        assert isinstance(j.get("events"), list)
        assert len(j.get("events")) == len(events)
    finally:
        try:
            c.close()
        except Exception:
            pass
