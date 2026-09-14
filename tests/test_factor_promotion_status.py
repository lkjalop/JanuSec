import pytest
from httpx import AsyncClient

from core.quality.factor_quality import get_quality_manager
from repositories import decisions_repo
from src.api.server import app


@pytest.mark.asyncio
async def test_factor_promotion_status_empty(monkeypatch):
    qm = get_quality_manager()
    qm.suppressed.clear()

    async def fake_list_recent(limit, tenant_id):
        return []
    monkeypatch.setattr(decisions_repo, 'list_recent', fake_list_recent)

    async with AsyncClient(app=app, base_url='http://test') as client:
        r = await client.get('/api/v1/factors/promotion/status', headers={'X-Tenant-ID':'tenant1'})
        assert r.status_code == 200
        body = r.json()
        assert body['tenant_id'] == 'tenant1'
        assert body['factors'] == []
        assert 'note' in body

@pytest.mark.asyncio
async def test_factor_promotion_status_with_counts_and_suppression(monkeypatch):
    qm = get_quality_manager()
    qm.suppressed.clear()
    qm.suppressed.add('lane_proc_parent_chain')

    sample_decisions = [
        {
            'event_id': 'e1',
            'factors': ['lane_proc_parent_chain','lane_ja3_rare','base_factor']
        },
        {
            'event_id': 'e2',
            'factors': ['lane_proc_parent_chain','corr_combo_factor']
        },
        {
            'event_id': 'e3',
            'factors': ['lane_ja3_rare']
        },
    ]

    async def fake_list_recent(limit, tenant_id):
        return sample_decisions

    monkeypatch.setattr(decisions_repo, 'list_recent', fake_list_recent)

    async with AsyncClient(app=app, base_url='http://test') as client:
        r = await client.get('/api/v1/factors/promotion/status', headers={'X-Tenant-ID':'tenantA'})
        assert r.status_code == 200
        body = r.json()
        factors = {f['factor']: f for f in body['factors']}
        assert 'lane_proc_parent_chain' in factors
        assert 'lane_ja3_rare' in factors
        assert 'corr_combo_factor' in factors
        assert factors['lane_proc_parent_chain']['suppressed'] is True
        assert factors['lane_proc_parent_chain']['status'] == 'observe'
        # lane_ja3_rare appears twice -> candidate threshold (>=3) not reached -> insufficient unless config changed
        assert factors['lane_ja3_rare']['observations'] == 2
        assert factors['lane_ja3_rare']['status'] in ('insufficient_data','candidate')
        # corr factor appears once
        assert factors['corr_combo_factor']['observations'] == 1
