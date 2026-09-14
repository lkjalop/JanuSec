import json
import math

import asyncio
import types

import pytest

# These tests exercise the FastAPI endpoints indirectly via a minimal ASGI call using app from api.app

@pytest.mark.asyncio
async def test_finops_overview_thresholds(monkeypatch):
    from src.api.app import app

    # Patch finops manager hourly_summary to return a deterministic series
    class DummyFM:
        def hourly_summary(self, tenant=None):
            # ascending costs -> threshold should be above ewma and latest under threshold
            hours = []
            base = 10.0
            for i in range(12):
                hours.append({'hour': i, 'cost_units': base + i})
            return {'hours': hours}

    def get_fm():
        return DummyFM()

    # Patch import in endpoint module path
    import api.finops_endpoints as fe
    monkeypatch.setattr(fe, 'get_finops_manager', get_fm)

    # Build request and call handler
    scope = {
        'type': 'http', 'asgi': {'version':'3.0','spec_version':'2.1'},
        'method':'GET','path':'/api/v1/finops/overview','query_string': b'',
        'headers':[], 'client':('test',0), 'server':('srv',0), 'scheme':'http','app': app,'state':{}
    }
    from starlette.requests import Request
    req = Request(scope)
    res = await fe.finops_overview(req, tenant_id=None, alpha=0.3, k=3.0)

    assert res['points'] == 12
    assert res['ewma'] is not None
    assert res['ewma_threshold'] is not None
    assert res['latest_cost'] == pytest.approx(21.0)
    # Increasing series with 3-sigma band -> not anomalous
    assert res['anomaly_flag'] is False


@pytest.mark.asyncio
async def test_finops_forecast_shape(monkeypatch):
    # Patch FinOps manager forecast to known output
    class DummyFM2:
        def forecast_month(self, tenant):
            return {'tenant': tenant or 'all', 'forecast_units': 123.45, 'basis_days': 7, 'avg_daily': 17.64}

    import api.metrics_status_endpoints as ms
    monkeypatch.setattr(ms, 'get_finops_manager', lambda: DummyFM2())

    # Direct call
    res = await ms.finops_forecast(tenant='acme')
    assert set(res.keys()) == {'tenant','forecast_units','basis_days','avg_daily'}
    assert res['tenant'] == 'acme'
    assert res['forecast_units'] == pytest.approx(123.45)
    assert res['basis_days'] == 7
