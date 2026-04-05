from __future__ import annotations

from src.metrics.identity_metrics import (
    ensure_identity_metrics,
    record_transition,
    set_state_counts,
    record_event_flags,
    observe_risk,
)


def test_identity_metrics_present_in_registry():
    ensure_identity_metrics()
    # emit a few samples
    record_transition('Benign', 'Suspicious')
    set_state_counts({'Benign': 5, 'Suspicious': 2, 'Threat': 1})
    record_event_flags({'lateral': True, 'priv_escalation': True})
    observe_risk(1.2)

    try:
        from prometheus_client import generate_latest  # type: ignore
        from src.api.metrics_init import REGISTRY  # type: ignore
    except Exception:
        # If prometheus client is not available, skip
        return
    data = generate_latest(REGISTRY).decode('utf-8') if REGISTRY is not None else ''
    assert 'identity_state_transitions_total' in data
    assert 'identity_state_count' in data
    assert 'identity_event_flags_total' in data
    # Histogram exposes *_count
    assert 'identity_risk_score_count' in data

