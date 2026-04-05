import traceback
import os
os.environ.setdefault('PLATFORM_LITE_INIT','1')
try:
    import src.api.collectors_api as cmod
    router = getattr(cmod, 'router', None)
    print('collectors_api imported:', cmod)
    print('router object:', router)
    if router is None:
        print('No router attribute on collectors_api')
    else:
        print('Router routes:')
        for r in router.routes:
            try:
                path = getattr(r, 'path', None) or str(r)
            except Exception:
                path = str(r)
            try:
                methods = getattr(r, 'methods', None)
            except Exception:
                methods = None
            print(' -', path, methods)
except Exception as e:
    print('Import failed:')
    traceback.print_exc()
