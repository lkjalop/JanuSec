import os
os.environ['PLATFORM_LITE_INIT']='1'
try:
    import importlib
    mod = importlib.import_module('src.api.kape_endpoints')
    print('kape module imported', hasattr(mod, 'router'))
    r = getattr(mod, 'router', None)
    print('router:', r)
    from src.api.kape_endpoints import router as rr
    print('router import ok', rr)
except Exception as e:
    print('import error', e)
