import pytest

def test_core_routers_mounted():
    # Import the app package; tests/conftest ensures src is on sys.path
    try:
        from src.api import app as appmod
    except Exception:
        # fallback for codebases exposing `app` directly under src.api.app
        import importlib
        appmod = importlib.import_module('src.api.app')

    app = getattr(appmod, 'app', None)
    assert app is not None, 'FastAPI app object missing from src.api.app'

    routes = {getattr(r, 'name', repr(r)) for r in app.routes}
    # Look for typical router fragments; this is intentionally fuzzy to avoid fragile names.
    assert any('decision' in rn.lower() or 'sse' in rn.lower() for rn in routes), (
        f'Decisions/SSE router not detected in app routes: {sorted(routes)[:20]}'
    )
