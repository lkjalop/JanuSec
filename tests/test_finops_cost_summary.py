import pytest


@pytest.mark.asyncio
async def test_finops_cost_summary_shape(monkeypatch):
    # Patch the overview, daily, and forecast functions on the metrics_status_endpoints module
    import api.metrics_status_endpoints as ms

    async def fake_overview():
        return {
            'latest_cost': 12.34,
            'ewma': 11.11,
            'ewma_threshold': 15.0,
            'anomaly_flag': False,
            'points': 7,
        }

    async def fake_daily():
        return {
            'day': '2025-10-04',
            'embedding_calls': 10,
            'reputation_queries': 5,
            'artifacts_processed': 100,
            'llm_tokens': 12345,
            'estimated_usd_day': 1.23,
            'estimated_usd_month_to_date': 45.6,
            'unit_prices': {'embed': 0.1}
        }

    async def fake_forecast(tenant: str | None = None):
        return {
            'tenant': tenant or 'all',
            'forecast_units': 99.9,
            'basis_days': 14,
            'avg_daily': 7.14,
        }

    monkeypatch.setattr(ms, 'finops_overview', fake_overview)
    monkeypatch.setattr(ms, 'finops_daily', fake_daily)
    monkeypatch.setattr(ms, 'finops_forecast', fake_forecast)

    # Call the combined endpoint function directly
    res = await ms.finops_cost_summary(tenant='acme')

    assert isinstance(res, dict)
    assert set(res.keys()) >= {'overview', 'daily', 'forecast'}

    # Overview sanity
    ov = res['overview']
    assert isinstance(ov, dict)
    assert set(ov.keys()) >= {'latest_cost', 'ewma', 'ewma_threshold', 'anomaly_flag'}

    # Daily sanity
    dly = res['daily']
    assert isinstance(dly, dict)
    assert set(dly.keys()) >= {
        'day', 'embedding_calls', 'reputation_queries', 'artifacts_processed',
        'llm_tokens', 'estimated_usd_day', 'estimated_usd_month_to_date'
    }

    # Forecast sanity
    fc = res['forecast']
    assert isinstance(fc, dict)
    assert set(fc.keys()) >= {'tenant', 'forecast_units', 'basis_days', 'avg_daily'}
    assert fc['tenant'] == 'acme'
