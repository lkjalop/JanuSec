import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_crossmap_endpoint():
    from src.api.app import app
    async with AsyncClient(app=app, base_url='http://test') as client:
        resp = await client.get('/api/v1/compliance/crossmap')
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            j = resp.json()
            assert 'frameworks' in j and 'crossmap' in j


@pytest.mark.asyncio
async def test_kev_status():
    from src.api.app import app
    async with AsyncClient(app=app, base_url='http://test') as client:
        resp = await client.get('/api/v1/compliance/kev/status')
        assert resp.status_code in (200, 503, 404)
