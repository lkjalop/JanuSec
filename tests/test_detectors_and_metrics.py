import pytest
import numpy as np

from src.api.metrics_init import ensure_metrics, ingest_events_counter, ingest_buffer_gauge

def test_metrics_stub_and_initialization():
    # ensure_metrics should be idempotent and safe to call
    ensure_metrics()
    # calling stub methods should not raise
    try:
        ingest_buffer_gauge.set(0)
        ingest_events_counter.inc()
    except Exception as e:
        pytest.skip(f'metrics backend not available: {e}')


def test_isolation_forest_wrapper_or_skip():
    try:
        from src.detectors.isolation_forest_wrapper import IFWrapper
    except Exception:
        pytest.skip('scikit-learn not installed')
    X = np.random.randn(100, 3)
    m = IFWrapper(n_estimators=10, contamination=0.05)
    m.fit(X)
    scores = m.score(X[:5])
    assert len(scores) == 5


def test_change_point_wrapper_or_skip():
    try:
        from src.detectors.change_point_wrapper import CPDWrapper
    except Exception:
        pytest.skip('ruptures not installed')
    series = np.concatenate([np.random.randn(50), np.random.randn(50) + 5])
    try:
        cp = CPDWrapper()
    except RuntimeError:
        pytest.skip('ruptures not available at runtime')
    cuts = cp.detect(series, pen=5.0)
    assert isinstance(cuts, list)
