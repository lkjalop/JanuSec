from fastapi.testclient import TestClient
from src.api.server import app
from src.api.alerts_endpoints import get_canonical_alert_ring

client = TestClient(app)
# synchronous post
r1 = client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantA'}, json={'id':'a1','details':{'process':{'name':'powershell.exe'}}})
print('post a1', r1.status_code, r1.text)
r2 = client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantB'}, json={'id':'b1','details':{'process':{'name':'powershell.exe'}}})
print('post b1', r2.status_code, r2.text)
ring, lock, maxlen = get_canonical_alert_ring()
print('ring len', len(ring))
for r in ring:
    print('RING ITEM', r)
