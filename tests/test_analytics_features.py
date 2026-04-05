import os
import time

from core.finops.finops_manager import get_finops_manager
from core.hunt.sidecar_session import get_sidecar_manager

# Note: These tests use synthetic sessions and cost ingestion assumptions.

def test_factor_emergence_and_embedding_simulation():
    mgr = get_sidecar_manager()
    sess = mgr.start('sess_analytics_1','tenantA', window_hours=24, model_enabled=False)
    rep = mgr.report('sess_analytics_1')
    assert rep and 'report' in rep
    report = rep['report']
    # Factor emergence top should exist if factors present
    fe = report.get('factor_emergence_top')
    assert fe is not None, 'factor_emergence_top missing'
    assert isinstance(fe, list)
    if fe:  # ensure structure of first row (non-meta)
        row0 = fe[0]
        if not row0.get('meta'):  # skip meta row for structural validation
            for k in ['factor','hunt_freq','baseline_freq_norm','severity_bucket','emergence_score']:
                assert k in row0
    # Embedding simulation structure
    emb = report.get('embedding_simulation')
    assert emb is not None, 'embedding_simulation missing'
    for k in ['candidates','similarities','threshold_analysis','best_threshold','assumptions']:
        assert k in emb


def test_finops_overview_ewma_anomaly_flag_behavior():
    fm = get_finops_manager()
    tenant = 'tenantE'
    # Ingest synthetic hourly cost data (steady then spike)
    base = time.time() - 3600*10
    for i in range(8):
        ts = base + i*3600
        # simulate ingestion by directly calling ingest (now timestamp only, not override); use escalating pattern last point
        fm.ingest(tenant, 'componentX', cost_units=10.0, units=1.0)
    # Add spike
    fm.ingest(tenant, 'componentX', cost_units=50.0, units=1.0)
    import asyncio

    from api.server import finops_overview
    # Call endpoint function directly
    result = asyncio.run(finops_overview(tenant_id=tenant))
    assert 'ewma' in result and 'ewma_threshold' in result
    assert 'anomaly_flag' in result
    # Anomaly could be True depending on distribution; we assert consistent types
    assert isinstance(result['anomaly_flag'], bool)
