"""Tests for SeasonalityDecomposer.

We synthesize a series with a repeating pattern and ensure seasonal component
captures average pattern and residual scores reflect outliers.
"""
from __future__ import annotations

from statistics import mean
from src.ml.seasonality import SeasonalityDecomposer


def _pattern_series(period: int = 6, repeats: int = 10, noise: float = 0.3):
    import random
    random.seed(123)
    base = [1.0, 2.0, 3.0, 2.0, 1.0, 0.0][:period]
    out = []
    for _ in range(repeats):
        for v in base:
            out.append(v + random.gauss(0, noise))
    return out


def test_auto_period_and_seasonal_component():
    series = _pattern_series()
    dec = SeasonalityDecomposer(auto=True)
    out = dec.batch_decompose(series)
    assert dec.state.period >= 4, "Expected a discovered period >= 4"
    # seasonal values should not all be zero once discovered
    assert any(step['seasonal'] != 0.0 for step in out[-dec.state.period:]), "Seasonal component not populated"


def test_residual_scores_increase_for_outlier():
    series = _pattern_series()
    dec = SeasonalityDecomposer(auto=True)
    out = dec.batch_decompose(series)
    # Inject an outlier at end and reprocess
    outlier_val = 10.0
    r = dec.ingest(outlier_val)
    # Severity should be noticeably higher than typical residual scores
    typical = [o['resid_score'] for o in out[-dec.state.period:]]
    assert r['resid_score'] > (sum(typical)/len(typical)) + 0.05, "Outlier residual severity not elevated"
