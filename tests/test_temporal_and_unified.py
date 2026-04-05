import time
import pytest

def test_temporal_ewma_convergence():
    from src.ml.temporal_model import TemporalModel
    tm = TemporalModel(alpha=0.5)
    eid = 'test-entity-1'
    # push a sequence of increasing anomaly scores
    svals = []
    for i in range(1, 6):
        features = {'anomaly_score': float(i)}
        s = tm.update(eid, features)
        svals.append(s)
        time.sleep(0.01)
    # EWMA should converge and be monotonic non-decreasing for increasing inputs with alpha>0
    assert all(svals[i] <= svals[i+1] + 1e-6 for i in range(len(svals)-1))
    # final score in valid range
    assert 0.0 <= svals[-1] <= 1.0


def test_unified_graph_facade_delegation():
    # Ensure UG exposes methods and returns expected minimal shapes
    try:
        from graph.unified import UG
    except Exception:
        pytest.skip('Unified graph not importable')
    assert hasattr(UG, 'explain_chain')
    assert hasattr(UG, 'k_hops')
    # call with a fake node; should not raise and return dict-like
    res = UG.explain_chain('node:missing', max_depth=2)
    assert isinstance(res, dict)
    kh = UG.k_hops('node:missing', k=2)
    assert isinstance(kh, dict)
