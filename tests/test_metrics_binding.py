from prometheus_client import generate_latest

from src.api.metrics_init import REGISTRY, ensure_metrics
from src.api.startup import initialize_platform_components


def test_metrics_binding_core_families_present():
    ensure_metrics()
    initialize_platform_components()
    payload = generate_latest(REGISTRY).decode()
    # Core families should be present with labels or at least defined
    assert 'rule_hits_total' in payload
    assert 'detection_sse_decisions_total' in payload
    assert 'decisions_total' in payload  # action dispatcher
    assert 'embedding_provider_selection_total' in payload
