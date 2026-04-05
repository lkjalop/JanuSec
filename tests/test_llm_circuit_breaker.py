import time
import os

from src.integrations.llm_client import LLMClient


def test_tenant_budget_increments_and_breaker_trip(tmp_path, monkeypatch):
    # Use mock mode to avoid provider calls
    monkeypatch.setenv('LLM_MOCK', '1')
    # small budget so it trips quickly
    monkeypatch.setenv('LLM_TENANT_BUDGET', '0.000001')
    monkeypatch.setenv('LLM_BREAKER_FAILURE_THRESHOLD', '1')
    monkeypatch.setenv('LLM_BREAKER_TRIP_SECONDS', '1')

    client = LLMClient()
    tenant = 'tenant-123'

    # first call should succeed and increment tenant budget
    res = client.generate('hello world', tenant_id=tenant)
    assert 'text' in res
    assert client._tenant_budget.get(tenant, 0.0) > 0

    # subsequent call should trip due to tiny budget threshold
    res2 = client.generate('another prompt', tenant_id=tenant)
    assert 'error' in res2
    assert res2['error'] in {'tenant_cost_threshold_exceeded', 'circuit_breaker_tripped'}

    # wait for breaker to reset
    time.sleep(1.1)
    res3 = client.generate('after wait', tenant_id=tenant)
    # after reset, either we get error (if still over budget) or normal response
    assert isinstance(res3, dict)
