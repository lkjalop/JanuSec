import pytest
from httpx import AsyncClient

from db.database import DatabaseNotAvailable, get_pool
from src.api.server import app
from src.repositories.hunt_lane_events_repo import HuntLaneEventsRepository


async def _make_repo() -> HuntLaneEventsRepository:
    try:
        pool = await get_pool()
    except DatabaseNotAvailable:
        pool = None
    repo = HuntLaneEventsRepository(pool)
    repo.require_tenant = True
    return repo


@pytest.mark.asyncio
async def test_hunt_lane_events_repo_requires_tenant():
    HuntLaneEventsRepository.reset_fallback()
    repo = await _make_repo()
    with pytest.raises(ValueError):
        await repo.recent(None, lane=None, limit=10)


@pytest.mark.asyncio
async def test_hunt_lane_events_repo_isolation():
    HuntLaneEventsRepository.reset_fallback()
    repo = await _make_repo()

    await repo.record('tenantA', 'evtA1', 'ja3_novelty', ['lane_ja3_rare'], 5.0)
    await repo.record('tenantB', 'evtB1', 'ja3_novelty', ['lane_ja3_rare'], 6.0)
    await repo.record('tenantA', 'evtA2', 'process_lineage', ['lane_proc_parent_chain'], 4.2)

    a_rows = await repo.recent('tenantA')
    b_rows = await repo.recent('tenantB')

    assert all(r['tenant_id'] == 'tenantA' for r in a_rows)
    assert all(r['tenant_id'] == 'tenantB' for r in b_rows)
    assert len(a_rows) == 2
    assert len(b_rows) == 1


@pytest.mark.asyncio
async def test_hunt_lane_events_api_isolation():
    HuntLaneEventsRepository.reset_fallback()
    repo = await _make_repo()

    await repo.record('tenantZ', 'evtZ1', 'ja3_novelty', ['lane_ja3_rare'], 5.5)
    await repo.record('tenantZ', 'evtZ2', 'process_lineage', ['lane_proc_parent_chain'], 5.1)
    await repo.record('tenantY', 'evtY1', 'process_lineage', ['lane_proc_parent_chain'], 7.0)

    from tests._helpers import default_test_headers
    async with AsyncClient(app=app, base_url="http://test") as client:
        hdrs_z = default_test_headers()
        hdrs_z.update({'X-Tenant-ID': 'tenantZ'})
        resp_z = await client.get('/api/v1/hunt/lanes/events', headers=hdrs_z)
        assert resp_z.status_code == 200
        data_z = resp_z.json()
        assert data_z['tenant_id'] == 'tenantZ'
        assert len(data_z['events']) == 2
        assert all(ev['tenant_id'] == 'tenantZ' for ev in data_z['events'])

        hdrs_y = default_test_headers()
        hdrs_y.update({'X-Tenant-ID': 'tenantY'})
        resp_y = await client.get('/api/v1/hunt/lanes/events', headers=hdrs_y)
        assert resp_y.status_code == 200
        data_y = resp_y.json()
        assert len(data_y['events']) == 1
        assert data_y['events'][0]['tenant_id'] == 'tenantY'

        resp_missing = await client.get('/api/v1/hunt/lanes/events')
        assert resp_missing.status_code in (400, 401, 403, 422)
