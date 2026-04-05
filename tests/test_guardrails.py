import asyncio
import types

import pytest

from api.server import _guardrail_single_pass
from src.api import runtime_state


class DummyMetrics:
    def __init__(self, drift=0.0):
        self.gauges = {'factor_freq_js_divergence': drift}

class DummyOrch:
    def __init__(self, drift=0.0):
        self.metrics = DummyMetrics(drift)

class MemAlertsRepo:
    def __init__(self):
        self.alerts = []
    async def insert_alert(self, tenant_id, category, severity, message, details, dedupe_hash):
        self.alerts.append({'tenant_id':tenant_id,'category':category,'severity':severity,'message':message,'details':details})
        return {'id': len(self.alerts)}

@pytest.mark.asyncio
async def test_guardrail_queue_and_drift(monkeypatch):
    from api import server
    # Monkeypatch queue stats
    monkeypatch.setattr(server,'EVENT_QUEUE', types.SimpleNamespace(stats=lambda: {'depth':90,'max_size':100}))
    repo = MemAlertsRepo()
    orch = DummyOrch(drift=0.5)
    try:
        runtime_state.DECISION_CACHE.clear()
    except Exception:
        try:
            for k in list(runtime_state.DECISION_CACHE.keys()):
                runtime_state.DECISION_CACHE.pop(k, None)
        except Exception:
            pass
    await _guardrail_single_pass(orch, repo, queue_util_threshold=0.8, drift_threshold=0.4, latency_thresh=9999,
                                 fallback_ratio_threshold=1.0, recent_fallback=[], recent_select=[])
    cats = {a['category'] for a in repo.alerts}
    assert 'queue' in cats
    assert 'drift' in cats

@pytest.mark.asyncio
async def test_guardrail_latency(monkeypatch):
    from api import server
    monkeypatch.setattr(server,'EVENT_QUEUE', types.SimpleNamespace(stats=lambda: {'depth':0,'max_size':100}))
    repo = MemAlertsRepo()
    orch = DummyOrch(drift=0.0)
    runtime_state.DECISION_CACHE.clear()
    # Insert 60 decisions with high latency
    for i in range(60):
        runtime_state.cache_set(f'e{i}', types.SimpleNamespace(processing_time_ms=5000, factors=['x']))
    await _guardrail_single_pass(orch, repo, queue_util_threshold=0.9, drift_threshold=1.0, latency_thresh=2000,
                                 fallback_ratio_threshold=1.0, recent_fallback=[], recent_select=[])
    assert any(a['category']=='latency' for a in repo.alerts)

@pytest.mark.asyncio
async def test_guardrail_embedding_fallback(monkeypatch):
    from api import server
    monkeypatch.setattr(server,'EVENT_QUEUE', types.SimpleNamespace(stats=lambda: {'depth':0,'max_size':100}))
    repo = MemAlertsRepo()
    orch = DummyOrch(drift=0.0)
    try:
        runtime_state.DECISION_CACHE.clear()
    except Exception:
        try:
            for k in list(runtime_state.DECISION_CACHE.keys()):
                runtime_state.DECISION_CACHE.pop(k, None)
        except Exception:
            pass
    # Simulate 120 selections where 30 have hash fallback indicator
    for i in range(120):
        factors = ['ok']
        if i % 4 == 0:  # 25%
            factors.append('hash_provider_used')
        runtime_state.cache_set(f'e{i}', types.SimpleNamespace(processing_time_ms=10, factors=factors))
    recent_fallback = []
    recent_select = []
    # Run enough passes to accumulate >=100 selections
    await _guardrail_single_pass(orch, repo, queue_util_threshold=1.0, drift_threshold=1.0, latency_thresh=9999,
                                 fallback_ratio_threshold=0.2, recent_fallback=recent_fallback, recent_select=recent_select)
    # After first pass total_sel may be <100 depending on window (we slice last 50). run extra passes
    for _ in range(3):
        await _guardrail_single_pass(orch, repo, queue_util_threshold=1.0, drift_threshold=1.0, latency_thresh=9999,
                                     fallback_ratio_threshold=0.2, recent_fallback=recent_fallback, recent_select=recent_select)
    assert any(a['category']=='embedding' for a in repo.alerts)
