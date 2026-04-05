import asyncio
import sys
from pathlib import Path
# Ensure repo root is on sys.path for direct script runs
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from httpx import AsyncClient
from src.api.server import app

async def main():
    async with AsyncClient(app=app, base_url='http://test') as client:
        await client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantA'}, json={'id':'a1','details':{'process':{'name':'powershell.exe'}}})
        await client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantB'}, json={'id':'b1','details':{'process':{'name':'powershell.exe'}}})
        rA = await client.get('/api/v1/alerts/recent?tenant_id=tenantA')
        rB = await client.get('/api/v1/alerts/recent?tenant_id=tenantB')
        rAll = await client.get('/api/v1/alerts/recent')
        print('rA', rA.status_code, rA.text)
        print('rB', rB.status_code, rB.text)
        print('rAll', rAll.status_code, rAll.text)

asyncio.run(main())
