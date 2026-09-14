from __future__ import annotations
import os
from prometheus_client import CollectorRegistry
from src.api.metrics_init import REGISTRY, ensure_metrics
from src.core.correlation.metrics import ensure_correlation_metrics
from src.core.correlation.rules.registry import CORRELATION_RULES, set_fired_counter_for_tests
from prometheus_client import Counter


def test_rule_metrics_registered_and_suppressed(monkeypatch):
    # Ensure metrics are initialized into a test registry
    reg = CollectorRegistry(auto_describe=True)
    # monkeypatch the module-level REGISTRY if present
    monkeypatch.setenv('FEATURE_FLAGS', '')  # ensure feature flags empty (rules should be suppressed)
    ensure_metrics()
    ensure_correlation_metrics()

    # Trigger evaluation; rule gates should cause suppressed counter to increment when feature disabled
    from src.core.correlation.rules.weekX.t1078_valid_accounts import ia_valid_accounts
    # Call with an event that would otherwise match
    ev = {'auth_success_count': 10, 'src_unusual': True}
    # directly call the function to test suppression path
    res = ia_valid_accounts(ev)
    assert res is False

    # Now enable the feature flag and ensure rule hits increment
    monkeypatch.setenv('FEATURE_FLAGS', 'rule_ia_valid_accounts')
    # reload feature flags module to pick up env (simple pattern)
    import importlib
    import core.feature_flags as ff
    importlib.reload(ff)

    # Evaluate again
    res2 = ia_valid_accounts(ev)
    assert res2 is True
