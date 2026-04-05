import importlib, sys, os
os.environ['TEST_HELPERS_ENABLED']='1'
print('TEST_HELPERS_ENABLED=', os.environ.get('TEST_HELPERS_ENABLED'))
# import server and alerts_endpoints
srv = importlib.import_module('src.api.server')
print('src.api.server in sys.modules?', 'src.api.server' in sys.modules)
print('server._ALERT_RING id,len=', id(getattr(srv, '_ALERT_RING', None)), len(getattr(srv, '_ALERT_RING', [])))
from src.api.alerts_endpoints import get_canonical_alert_ring, ALERT_RING as AE_RING
cr, cl, cm = get_canonical_alert_ring()
print('canonical ring id,len=', id(cr), len(cr))
# append to server's ring
lock = getattr(srv, '_ALERT_RING_LOCK', None)
if lock is not None:
    try:
        with lock:
            srv._ALERT_RING.append({'id':'x1','ts':1,'host':'h1','verdict':'ALERT','score':0.9})
    except Exception as e:
        print('append with lock failed', e)
else:
    srv._ALERT_RING.append({'id':'x1','ts':1,'host':'h1','verdict':'ALERT','score':0.9})
print('after append server._ALERT_RING len=', len(srv._ALERT_RING))
# Now scan sys.modules for _ALERT_RING lists
rings = []
for m in list(sys.modules.values()):
    try:
        r = getattr(m, '_ALERT_RING', None)
        if isinstance(r, list):
            rings.append((getattr(m,'__name__',str(m)) if m else str(m), id(r), len(r)))
    except Exception:
        pass
print('found rings (first 10):', rings[:10])
cr2, cl2, cm2 = get_canonical_alert_ring()
print('canonical after:', id(cr2), len(cr2))
# Try import alerts_endpoints and look at its ALERT_RING
ae = importlib.import_module('src.api.alerts_endpoints')
print('alerts_endpoints.ALERT_RING id,len=', id(getattr(ae,'ALERT_RING',None)), len(getattr(ae,'ALERT_RING',[])))
print('done')
