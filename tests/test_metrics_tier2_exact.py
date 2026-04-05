import os
import json
import time

import pytest

os.environ['METRICS_TEST_MODE'] = '1'
from src.api import insights_endpoints as ie
from src.api.metrics_init import REGISTRY


def test_tier2_metrics_increment(monkeypatch):
    # Ensure metrics registered
    try:
        from src.api.metrics_init import ensure_metrics
        ensure_metrics()
    except Exception:
        pass

    # Prepare a small batch
    payload = {'assessment_id': 'test-assess', 'rows': [{'row_index': 1, 'raw': {'sha256': 'a'}}, {'row_index':2,'raw':{'sha256':'b'}}], 'pipeline_context': {}}
    resp = None
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        resp = loop.run_until_complete(ie.tier2_enrich_batch(payload, request=None))
    except Exception:
        # fallback: call directly
        resp = ie.tier2_enrich_batch(payload, request=None)

    assert resp is not None
    # Inspect in-memory metrics via REGISTRY._dummy_samples if available
    ds = getattr(REGISTRY, '_dummy_samples', None) or {}
    # TIER2_COMPLETED should have incremented by number of rows (2)
    found = False
    for k, samples in ds.items():
        if 'tier2_completed_total' in k:
            found = True
            # Expect at least one sample with value 2
            values = [getattr(s, 'value', None) for s in samples]
            assert any(v == 2 or v == '2' or float(v) == 2.0 for v in values)
    assert found, 'tier2_completed_total not found in dummy samples' 
