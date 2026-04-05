import asyncio
import os

os.environ['ALLOW_DEFAULT_TENANT'] = '1'
# Prefer in-memory behavior for clarity
os.environ['ALERTS_PERSIST_HISTORY'] = '0'

from httpx import AsyncClient
from src.api.server import app
from src.api.alerts_endpoints import ALERT_RING, ALERT_RING_LOCK
from src.api.dependencies import get_platform_state

async def main():
    async with AsyncClient(app=app, base_url='http://test') as client:
        await client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantA'}, json={'id':'a1','details':{'process':{'name':'powershell.exe'}}})
        await client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantB'}, json={'id':'b1','details':{'process':{'name':'powershell.exe'}}})
        rA = await client.get('/api/v1/alerts/recent?tenant_id=tenantA')
        rB = await client.get('/api/v1/alerts/recent?tenant_id=tenantB')
        rAll = await client.get('/api/v1/alerts/recent')
        print('rA', rA.status_code, rA.json())
        print('rB', rB.status_code, rB.json())
        print('rAll', rAll.status_code, rAll.json())
        ps = get_platform_state()
        print('platform recent:', [d for d in ps.recent_alerts(limit=10)])
        with ALERT_RING_LOCK:
            print('ALERT_RING:', list(ALERT_RING))

if __name__ == '__main__':
    asyncio.run(main())
