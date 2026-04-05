import os, json, inspect, sys
# Ensure repo root is importable when running as a script
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
os.environ['API_KEYS_JSON'] = json.dumps([{'key':'k3','scopes':['factors.search','recalibrator.admin']}])
from src.api.server import app
for r in app.router.routes:
    if getattr(r, 'path', '') == '/api/v1/playbook/request' and 'POST' in getattr(r, 'methods', []):
        print('Route:', r.path, type(r))
        ep = getattr(r, 'endpoint', None)
        print('Endpoint:', ep)
        try:
            print('endpoint name:', getattr(ep, '__name__', None))
            print('signature:', inspect.signature(ep))
        except Exception as e:
            print('sig err', e)
        # inspect wrappers
        w = ep
        depth = 0
        while w and depth < 10:
            print('depth', depth, 'repr', w)
            print('   __name__', getattr(w, '__name__', None))
            print('   __qualname__', getattr(w, '__qualname__', None))
            print('   __wrapped__', getattr(w, '__wrapped__', None))
            print('   __signature__', getattr(w, '__signature__', None))
            w = getattr(w, '__wrapped__', None)
            depth += 1
        break
else:
    print('route not found')
