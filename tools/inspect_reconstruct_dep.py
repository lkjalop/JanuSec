import os
os.environ['PYTEST_CURRENT_TEST'] = '1'
os.environ['TEST_HELPERS_ENABLED'] = '1'
os.environ['PLATFORM_LITE_INIT'] = '1'

from src.api.server import app
import inspect

print('App router routes count:', len(list(app.router.routes)))
for r in app.router.routes:
    p = getattr(r, 'path', None) or getattr(r, 'path_regex', None)
    if p and '/api/v1/graph/reconstruct' in str(p):
        print('\nFOUND ROUTE:', r)
        dep = getattr(r, 'dependant', None)
        if dep is None:
            print('No dependant attribute')
        else:
            print('Endpoint call:', getattr(dep, 'call', None))
            print('Endpoint signature:', inspect.signature(dep.call))
            print('\nRoot dependencies:')
            for i, sub in enumerate(dep.dependencies or []):
                fn = getattr(sub, 'call', None)
                try:
                    sig = inspect.signature(fn)
                except Exception:
                    sig = None
                print(f' [{i}]', fn, 'sig=', sig)
                # list param names if possible
                try:
                    params = list(sig.parameters.keys()) if sig else []
                except Exception:
                    params = []
                print('     params:', params)
        # Also show route endpoint (FastAPI-wrapped)
        try:
            ep = r.endpoint if hasattr(r, 'endpoint') else None
            print('\nRoute endpoint function:', ep)
            print('Route endpoint signature:', inspect.signature(ep))
        except Exception as e:
            print('Could not inspect route endpoint:', e)
        break
print('\nDone')
