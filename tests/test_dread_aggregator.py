from __future__ import annotations

from src.explain.dread_aggregator_clean import aggregate


def test_dread_aggregate_basic():
    inp = {'cvss': 9.8, 'kev': True, 'epss': 0.8, 'anomaly': 0.7, 'path_length': 3}
    out = aggregate(inp)
    assert 0.0 <= out['damage'] <= 1.0
    assert out['exploit'] > 0.0
    assert out['repro'] <= 1.0
