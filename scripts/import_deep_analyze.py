import sys
sys.path.insert(0, '.')
import importlib
try:
    m = importlib.import_module('src.api.deep_analyze_endpoints')
    print('IMPORTED_OK', m)
    print('HAS_ROUTER', hasattr(m, 'router'), type(getattr(m,'router',None)))
    try:
        print('ROUTER_PATHS:', [getattr(r,'path',None) for r in getattr(m,'router').routes])
    except Exception as e:
        print('ROUTER_PATHS_ERR', e)
except Exception as e:
    print('IMPORT_ERROR', repr(e))
    raise
