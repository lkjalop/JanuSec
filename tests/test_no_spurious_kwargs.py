import os, sys
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

os.environ.setdefault('TEST_HELPERS_ENABLED', '1')

from src.api.server import app
from fastapi.routing import APIRoute


def test_calibration_auto_accept_has_no_kwargs_query_param():
    for r in app.router.routes:
        if not isinstance(r, APIRoute):
            continue
        if getattr(r, 'path', '') == '/api/v1/risk/calibration/auto_accept':
            params = [p.name for p in getattr(r.dependant, 'query_params', [])]
            assert 'kwargs' not in params and 'args' not in params
            return
    # route not found is also a failure for test expectations
    assert False, 'calibration_auto_accept route not registered'
