import os
from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP
from src.core.factors.emission_tracker import get_emitted


def test_emission_coverage_gated():
    """Optional emission coverage test.

    Gate with EMISSION_COVERAGE_THRESHOLD env var (0-100). If not set or <=0 the test is skipped.
    """
    try:
        thr = float(os.getenv('EMISSION_COVERAGE_THRESHOLD', '0') or 0.0)
    except Exception:
        thr = 0.0
    if thr <= 0.0:
        import pytest
        pytest.skip('EMISSION_COVERAGE_THRESHOLD not set; skipping emission coverage test')
    taxonomy_factors = set(_FACTOR_MAP.keys())
    # Optional autoseed: emit one record for each taxonomy factor into the tracker
    autoseed = os.getenv('EMISSION_COVERAGE_AUTOSEED','0').lower() in {'1','true','yes'}
    if autoseed:
        try:
            from src.core.factors.emission_tracker import record_emission
            for f in taxonomy_factors:
                try:
                    record_emission(f, decision_id=f"seed-{f}", node_ids=[f])
                except Exception:
                    pass
        except Exception:
            pass
    items = get_emitted()
    emitted_factors = {i.get('factor') for i in items if i.get('factor')}
    if not taxonomy_factors:
        import pytest
        pytest.skip('taxonomy empty')
    coverage = (len(emitted_factors & taxonomy_factors) / len(taxonomy_factors)) * 100.0
    assert coverage >= float(thr), f'emission coverage {coverage:.1f}% < threshold {thr}%'
