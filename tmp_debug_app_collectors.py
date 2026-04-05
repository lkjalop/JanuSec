import os, types, sys
os.environ.setdefault('PLATFORM_LITE_INIT','1')
# Stub heavy modules to speed import
for mod in ('scipy','numpy','pandas'):
    if mod not in sys.modules:
        sys.modules[mod] = types.ModuleType(mod)
# Import app module
import importlib
app_mod = importlib.import_module('src.api.app')
print('collectors_api_router in app_mod globals?', 'collectors_api_router' in app_mod.__dict__)
print('collectors_api_router value:', type(app_mod.__dict__.get('collectors_api_router')))
# Print whether route exists
from src.api.collectors_api import router as collectors_router
print('collectors_api.router routes:', [getattr(r,'path',str(r)) for r in collectors_router.routes])
print('app.router contains /collectors/run?', any(getattr(r,'path',None)=='/collectors/run' for r in app_mod.app.router.routes))
# Dump first 10 paths
print('first 20 app routes:')
for r in list(app_mod.app.router.routes)[:20]:
    print(' -', getattr(r,'path',str(r)))
