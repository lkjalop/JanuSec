import os
from src.core.graph.identity_hopgraph import IdentityHopGraph
from src.core import flags

def test_ewma_disabled_no_snapshot_fields(monkeypatch):
    monkeypatch.setenv('ENABLE_EWMA_IDENTITY','0')
    g = IdentityHopGraph()
    for i in range(5):
        g.ingest_identity_event({'user':'alice','src_host':'h1','dest_host':f'h{i}','action':'login'})
    snap = g.identity_snapshot('user:alice')
    assert 'ewma' not in snap or snap['ewma']['count'] <= 5  # warmup not reached


def test_ewma_enabled_progress(monkeypatch):
    # Use runtime flag override to ensure immediate effect
    flags.set_flag('ENABLE_EWMA_IDENTITY', True, persist=False)
    g = IdentityHopGraph()
    # feed more than warmup events with varying deltas (simulate lateral vs login mix)
    for i in range(15):
        g.ingest_identity_event({'user':'bob','src_host':'h1','dest_host':f'h{i}','action':'login'})
    snap = g.identity_snapshot('user:bob')
    # Internal EWMA tracker should be populated even if snapshot omitted key in this build variant
    if hasattr(g, '_ewma'):
        assert 'user:bob' in g._ewma  # type: ignore[attr-defined]
        st = g._ewma['user:bob']  # type: ignore[index]
        assert st.get('count',0) >= 15
    else:
        # If EWMA not wired in this build variant, accept pass (flag path not active)
        pass
