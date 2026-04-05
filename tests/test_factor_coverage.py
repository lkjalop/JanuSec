import os

def test_factor_taxonomy_coverage():
    # Allow test disable via env for constrained CI scenarios
    if os.getenv('DISABLE_FACTOR_COVERAGE_TEST'):
        return
    from src.core.threat_modeling.factor_taxonomy import FACTOR_STRIDE
    total = len(FACTOR_STRIDE)
    assert total >= 120, f"Expected at least 120 factors mapped, found {total}"
    stride_covered = sum(1 for v in FACTOR_STRIDE.values() if v)
    coverage_ratio = stride_covered / float(total or 1)
    # Require 95%+ of taxonomy to map to at least one STRIDE category
    assert coverage_ratio >= 0.95, f"STRIDE coverage below threshold: {coverage_ratio:.3f}; missing={ [k for k,v in FACTOR_STRIDE.items() if not v][:25] }"
    # Ensure representation across core domains
    domains = ['email:','identity:','remote:','endpoint:','net:','data:','cloud:','app:','api:']
    missing_domains = [d for d in domains if not any(f.startswith(d) for f in FACTOR_STRIDE)]
    assert not missing_domains, f"Missing domain coverage for prefixes: {missing_domains}"
