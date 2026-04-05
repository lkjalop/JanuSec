import os
os.environ['PYTEST_CURRENT_TEST']='1 (probe)'
try:
    from src.api.alerts_endpoints import get_canonical_alert_ring, ALERT_RING as AE_RING
    from src.api.server import _ALERT_RING as S_RING
    print('AE_RING id', id(AE_RING), 'len', len(AE_RING))
    print('S_RING id', id(S_RING), 'len', len(S_RING))
    try:
        cr, cl, cm = get_canonical_alert_ring()
        print('get_canonical id', id(cr), 'len', len(cr))
    except Exception as e:
        print('get_canonical failed', e)
except Exception as e:
    print('probe failed', e)
