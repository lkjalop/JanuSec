import importlib
import traceback
try:
    mod = importlib.import_module('src.api.deep_analyze_endpoints')
    print('OK import, router present:', hasattr(mod, 'router'))
    try:
        print('Sample routes:', [r.path for r in getattr(mod, 'router').routes][:10])
    except Exception as e:
        print('router routes inspect failed:', e)
except Exception:
    traceback.print_exc()