import os
import pytest
from src.api.metrics_tenant_helper import emit_labels_with_guard

class DummyRuntime:
    def __init__(self, tenants):
        self.tenants = tenants

@pytest.mark.parametrize("max_tenants,active_tenants,expected_tenant", [
    (10, ["a","b"], "a"),   # allowed: tenant label present
    (1, ["a","b"], ""),    # suppressed: tenant label is empty string
])
def test_emit_labels_with_guard(monkeypatch, max_tenants, active_tenants, expected_tenant):
    monkeypatch.setenv("METRICS_MAX_TENANTS", str(max_tenants))
    runtime = DummyRuntime(active_tenants)
    base = {}
    tenant = "a"
    labels = emit_labels_with_guard(runtime, base, tenant)
    assert "tenant" in labels
    assert labels["tenant"] == expected_tenant
    # Always returns a dict with 'tenant' key
    assert isinstance(labels, dict)
    # If suppressed, tenant is ''
    if max_tenants < len(active_tenants):
        assert labels["tenant"] == ""
    else:
        assert labels["tenant"] == tenant
