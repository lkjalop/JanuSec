import os, time
os.environ['PYTEST_CURRENT_TEST']='1'
from src.api.dependencies import get_canonical_alert_ring
from src.api import alerts_endpoints
from src.api import server as srv
from src.api.alerts_endpoints import append_alert

print('server._ALERT_RING id=', id(srv._ALERT_RING), 'len=', len(srv._ALERT_RING))
cr, cl, cm = get_canonical_alert_ring()
print('canonical_ring id=', id(cr), 'len=', len(cr))
print('alerts_endpoints.ALERT_RING id=', id(alerts_endpoints.ALERT_RING), 'len=', len(alerts_endpoints.ALERT_RING))
alert={'id':'dbg1','ts':time.time(),'host':'h'}
print('\nCalling append_alert(alert)')
append_alert(alert)
print('\nAfter append:')
print('server._ALERT_RING id=', id(srv._ALERT_RING), 'len=', len(srv._ALERT_RING))
cr2, cl2, cm2 = get_canonical_alert_ring()
print('canonical_ring id=', id(cr2), 'len=', len(cr2))
print('alerts_endpoints.ALERT_RING id=', id(alerts_endpoints.ALERT_RING), 'len=', len(alerts_endpoints.ALERT_RING))

# show first few items
print('\ncanonical ring items ids:', [i.get('id') for i in list(cr2)])
print('server ring items ids:', [i.get('id') for i in list(srv._ALERT_RING)])
print('alerts_endpoints ring items ids:', [i.get('id') for i in list(alerts_endpoints.ALERT_RING)])
