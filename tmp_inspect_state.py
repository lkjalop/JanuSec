from fastapi.testclient import TestClient
from src.api.server import app
from src.api.alerts_endpoints import get_canonical_alert_ring
from src.api.dependencies import get_platform_state

client = TestClient(app)
client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantA'}, json={'id':'a1','details':{'process':{'name':'powershell.exe'}}})
client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantB'}, json={'id':'b1','details':{'process':{'name':'powershell.exe'}}})
ps = get_platform_state()
print('platform_state_alerts_len', len(ps._alerts))
for a in ps._alerts:
    print('STATE ALERT', a)
ring, lock, maxlen = get_canonical_alert_ring()
print('ring len', len(ring))
for r in ring:
    print('RING ITEM', r)
