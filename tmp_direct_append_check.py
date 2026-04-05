import os, sys, time
os.environ['PYTEST_CURRENT_TEST']='1'
from src.api.alerts_endpoints import append_alert, get_canonical_alert_ring, ALERT_RING
from src.api.server import _ALERT_RING
print('before: alerts_endpoints.ALERT_RING id,len=', id(ALERT_RING), len(ALERT_RING))
try:
    cr, cl, cm = get_canonical_alert_ring()
    print('before: canonical id,len=', id(cr), len(cr))
except Exception as e:
    print('get_canonical_alert_ring exception', e)
print('before: server _ALERT_RING id,len=', id(_ALERT_RING), len(_ALERT_RING))
alert = {'id':'X1','ts':time.time(), 'tenant_id':None}
append_alert(alert)
print('after append: alerts_endpoints.ALERT_RING id,len=', id(ALERT_RING), len(ALERT_RING))
try:
    cr, cl, cm = get_canonical_alert_ring()
    print('after: canonical id,len=', id(cr), len(cr))
except Exception as e:
    print('get_canonical_alert_ring exception after', e)
print('after append: server _ALERT_RING id,len=', id(_ALERT_RING), len(_ALERT_RING))
# enumerate modules with _ALERT_RING
mods=[]
for m in list(sys.modules.values()):
    try:
        if getattr(m,'_ALERT_RING', None) is not None:
            mods.append((getattr(m,'__name__',str(m)), id(getattr(m,'_ALERT_RING')), len(getattr(m,'_ALERT_RING'))))
    except Exception:
        pass
print('module_rings_count=', len(mods))
for name,rid,ln in mods[:60]:
    print(name, rid, ln)
