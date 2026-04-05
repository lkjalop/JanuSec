from prometheus_client import generate_latest

from src.api.metrics_init import REGISTRY, ensure_metrics
from src.api.startup import initialize_platform_components


def collect_names():
    payload = generate_latest(REGISTRY).decode()
    names = set()
    for line in payload.splitlines():
        if line.startswith('# HELP'):
            parts = line.split()
            if len(parts) >= 3:
                # format: # HELP <metric_name> <rest>
                names.add(parts[2])
    return names, payload

def test_metrics_idempotent_registration():
    # First init
    ensure_metrics()
    initialize_platform_components()
    names1, payload1 = collect_names()
    # Second init (should not duplicate or error)
    initialize_platform_components()
    names2, payload2 = collect_names()
    # Core rule engine counter
    assert 'rule_hits_total' in payload2
    # Correlation engine counters (at least the main ones)
    assert 'hunt_correlation_rule_hits_total' in payload2
    assert 'hunt_correlation_factors_total' in payload2
    # Name sets unchanged (no duplicate families created)
    assert names1 == names2
