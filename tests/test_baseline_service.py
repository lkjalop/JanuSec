import asyncio
import pytest
from core.baseline_service import BASELINES, _ANOMALY_Z


@pytest.mark.asyncio
async def test_baseline_service_basic_anomaly():
    # Reset store
    try:
        BASELINES._store.clear()
    except Exception:
        pass
    for v in [10,10,10,10,10,10]:
        await BASELINES.update('host','h1','score',v)
    res = await BASELINES.get_z('host','h1','score',10)
    assert abs(res['z']) < 1e-6
    res2 = await BASELINES.get_z('host','h1','score', 10 + 5*_ANOMALY_Z)
    assert res2['anomaly'] is True


def test_baseline_service_placeholder():
    # Simple placeholder to keep at least one synchronous test present
    assert True
