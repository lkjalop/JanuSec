import asyncio
import json
from httpx import AsyncClient
from src.api.server import app

async def main():
    async with AsyncClient(app=app, base_url='http://test') as client:
        r = await client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantA'}, json={'id':'a1','details':{'process':{'name':'powershell.exe'}}})
        print('post A', r.status_code, r.text)
        r = await client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantB'}, json={'id':'b1','details':{'process':{'name':'powershell.exe'}}})
        print('post B', r.status_code, r.text)
        # Inspect various module-level state holders
        try:
            import src.api.dependencies as deps
            import src.api.alerts_endpoints as alerts_mod
            print('deps._PLATFORM_STATE id', id(getattr(deps, '_PLATFORM_STATE', None)))
            try:
                print('alerts_mod.ALERT_RING id', id(getattr(alerts_mod, 'ALERT_RING', None)), 'len', len(getattr(alerts_mod, 'ALERT_RING', [])))
            except Exception:
                pass
        except Exception as e:
            print('module inspect failed', e)
        rA = await client.get('/api/v1/alerts/recent?tenant_id=tenantA')
        print('rA', rA.status_code, rA.text)
        rB = await client.get('/api/v1/alerts/recent?tenant_id=tenantB')
        print('rB', rB.status_code, rB.text)
        rAll = await client.get('/api/v1/alerts/recent')
        print('rAll', rAll.status_code, rAll.text)

asyncio.run(main())
