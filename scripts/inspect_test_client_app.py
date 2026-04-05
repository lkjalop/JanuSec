import os, sys, json, importlib
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
# Mirror test module env
os.environ['API_KEYS_JSON'] = json.dumps([{'key': 'k3', 'scopes': ['factors.search', 'recalibrator.admin']}])
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
# Import the test module (it creates TestClient at import time)
import tests.test_auto_accept_and_repo as tmod
print('Imported test module, client:', getattr(tmod, 'client', None))
client = getattr(tmod, 'client', None)
if client is None:
    print('No client found in test module')
    sys.exit(1)
app = client.app
print('App routes:')
from fastapi.routing import APIRoute
for r in app.router.routes:
    if not isinstance(r, APIRoute):
        continue
    params = [p.name for p in getattr(r.dependant, 'query_params', [])]
    if 'kwargs' in params or 'args' in params:
        print('Route', r.path, 'params', params)
# Specifically inspect calibration_auto_accept
for r in app.router.routes:
    if getattr(r, 'path','') == '/api/v1/risk/calibration/auto_accept':
        params = [p.name for p in getattr(r.dependant, 'query_params', [])]
        print('calibration_auto_accept params:', params)
        ep = getattr(r, 'endpoint', None)
        import inspect
        try:
            print('endpoint sig:', inspect.signature(ep))
        except Exception as e:
            print('sig err', e)
        w = ep
        depth=0
        while w and depth<8:
            print('depth', depth, 'obj', w, 'name', getattr(w,'__name__',None), '__signature__', getattr(w,'__signature__',None))
            w = getattr(w,'__wrapped__',None)
            depth+=1
        break
else:
    print('calibration_auto_accept route not found')
