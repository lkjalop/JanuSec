"""Tests for EnsembleAnomaly scorer."""
from __future__ import annotations

from src.ml.ensemble_anomaly import EnsembleAnomaly


def test_basic_mad_scoring_increases_on_outlier():
    series = [10.0] * 20 + [25.0]  # clear outlier at end
    ea = EnsembleAnomaly(window=64)
    out = ea.batch_score(series)
    base_scores = [o['score'] for o in out[:-1]]
    assert out[-1]['score'] >= max(base_scores), "Outlier score not elevated"
    assert out[-1]['method'] in {'iso','mad'}


def test_features_vector_shape():
    series = [float(i) for i in range(15)]
    ea = EnsembleAnomaly(window=32)
    out = ea.batch_score(series)
    last = out[-1]
    feats = last['features']
    assert isinstance(feats, list) and len(feats) == 4, "Feature vector should have length 4"
    assert 'ewma' in last
