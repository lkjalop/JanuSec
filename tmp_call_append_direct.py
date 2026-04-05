import os, time
os.environ['PYTEST_CURRENT_TEST'] = '1'
from src.api.dependencies import get_canonical_alert_ring
from src.api.server import _ALERT_RING as server_ring
from src.api.server import _ALERT_RING_LOCK as server_lock
from src.api.alerts_endpoints import append_alert
print('server_ring id=', id(server_ring), 'len=', len(server_ring))
cr, cl, cm = get_canonical_alert_ring()
print('canonical_ring id=', id(cr), 'len=', len(cr))
alert = {'id':'direct1','ts': time.time(), 'host':'h', 'rule_id':'r1'}
append_alert(alert)
print('after append: server_ring id=', id(server_ring), 'len=', len(server_ring))
cr2, cl2, cm2 = get_canonical_alert_ring()
print('after append: canonical_ring id=', id(cr2), 'len=', len(cr2))
# enumerate modules with _ALERT_RING
import sys
mods=[]
for m in list(sys.modules.values()):
    try:
        cand = getattr(m,'_ALERT_RING', None)
        if cand is not None:
            mods.append((getattr(m,'__name__',str(m)), id(cand), len(cand)))
    except Exception:
        pass
print('module_rings_count=', len(mods))
for name,rid,ln in mods[:40]:
    print(name, rid, ln)
