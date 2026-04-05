import importlib, traceback
try:
    m = importlib.import_module('src.api.endpoint_malware_endpoints')
    print('loaded prefix', getattr(m,'router',None) and m.router.prefix)
except Exception:
    traceback.print_exc()
