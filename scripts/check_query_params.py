import os, sys
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
os.environ['PYTEST_CURRENT_TEST'] = '1'
# Ensure permissive test helpers enabled
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
import inspect
from src.api.server import app
from fastapi.routing import APIRoute

found = []
for r in app.router.routes:
    if not isinstance(r, APIRoute):
        continue
    params = [p.name for p in getattr(r.dependant, 'query_params', [])]
    if 'kwargs' in params or 'args' in params:
        found.append((r.path, params, r.dependant))

if not found:
    print('No routes expose args/kwargs as query params')
else:
    for path, params, dep in found:
        print('Route', path)
        print(' params:', params)
        try:
            ep = getattr(dep, 'call', None) or getattr(r, 'endpoint', None)
            print(' dependant.call:', ep)
        except Exception:
            pass
        print('-----')
