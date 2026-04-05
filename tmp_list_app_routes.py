import os, sys
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
# Ensure we import the same module path used by tests
from src.api import app as app_mod
try:
    a = getattr(app_mod, 'app', None) or getattr(app_mod, 'create_app', None) and app_mod.app
except Exception:
    a = getattr(app_mod, 'app', None)
print('module:', app_mod.__name__)
print('app_obj:', a)
print('id(app):', id(a))
try:
    routes = sorted({getattr(r, 'path', str(r)) for r in a.router.routes})
except Exception:
    routes = sorted({getattr(r, 'path', str(r)) for r in a.routes})
print('routes count:', len(routes))
for p in routes:
    print(p)
# inspect sys.modules for possible duplicates
candidates = [k for k in sys.modules.keys() if k.endswith('.api.app') or k.endswith('api.app')]
print('api.app modules in sys.modules:')
for k in candidates:
    print(k)
print('done')
