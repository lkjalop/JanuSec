import os
from src.api.server import app


def test_no_spurious_kwargs_in_routes():
    """Fail if any APIRoute exposes 'args' or 'kwargs' as query params unintentionally.

    Some routes legitimately declare a 'kwargs' query param (allowlist); those are
    excluded. This test guards against decorators leaking generic **kwargs
    signatures into FastAPI parameter generation.
    """
    allow_paths = {
        '/api/v1/graph/session/build',
        '/api/v1/risk/calibration/export',
    }
    offending = []
    for r in app.router.routes:
        dp = getattr(r, 'dependant', None)
        if not dp:
            continue
        names = {getattr(p, 'name', None) for p in dp.query_params}
        if 'args' in names or 'kwargs' in names:
            path = getattr(r, 'path', None)
            if path in allow_paths:
                continue
            offending.append((path, sorted(n for n in names if n in {'args', 'kwargs'})))
    assert not offending, f'Found routes exposing args/kwargs query params: {offending}'
