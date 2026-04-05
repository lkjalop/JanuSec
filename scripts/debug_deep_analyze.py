import importlib, traceback, sys, os
# ensure repo root is first so 'src' package resolves
root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root not in sys.path:
    sys.path.insert(0, root)
from src.api import app as appmod
app = appmod.app
print('app has routes before include:', any('/api/v1/assessments/deep_analyze' in getattr(r,'path','') for r in app.router.routes))
try:
    m = importlib.import_module('src.api.deep_analyze_endpoints')
    print('imported module:', m.__name__)
    router = getattr(m, 'router', None)
    print('router obj:', bool(router), 'prefix:', getattr(router,'prefix',None))
    try:
        app.include_router(router)
        print('include_router called')
    except Exception:
        print('include_router raised:')
        traceback.print_exc()
except Exception:
    print('import raised:')
    traceback.print_exc()
print('app has routes after include:', any('/api/v1/assessments/deep_analyze' in getattr(r,'path','') for r in app.router.routes))
print('\nList of assessments routes:')
for r in sorted({getattr(r,'path',str(r)) for r in app.router.routes}):
    if '/api/v1/assessments' in r:
        print(r)
