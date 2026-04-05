from fastapi.testclient import TestClient
from src.api.server import app
from src.api.alerts_endpoints import ALERT_RING, ALERT_RING_LOCK, ALERT_RING_MAX, get_canonical_alert_ring
from src.api.dependencies import get_platform_state

client = TestClient(app)
client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantA'}, json={'id':'a1','details':{'process':{'name':'powershell.exe'}}})
client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantB'}, json={'id':'b1','details':{'process':{'name':'powershell.exe'}}})
print('MODULE ALERT_RING len', len(ALERT_RING))
print('ALERT_RING items:', ALERT_RING)
ring, lock, maxlen = get_canonical_alert_ring()
print('CANONICAL RING len', len(ring))
print('CANONICAL RING items', ring)
ps = get_platform_state()
print('PLATFORM_STATE alerts len', len(ps._alerts))
print('PLATFORM_STATE alerts', list(ps._alerts))
