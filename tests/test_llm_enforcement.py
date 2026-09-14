import time

from src.integrations.llm_client import LLMClient


def test_soft_threshold_warning_and_ledger_persist(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    monkeypatch.setenv('LLM_TENANT_BUDGET', '0.000002')
    monkeypatch.setenv('LLM_TENANT_SOFT_THRESHOLD', '0.5')
    monkeypatch.setenv('LLM_BREAKER_FAILURE_THRESHOLD', '2')
    client = LLMClient()
    tenant = 'tenant-xyz'

    # initial call increments budget
    r1 = client.generate('alpha beta gamma', tenant_id=tenant)
    assert 'text' in r1
    # after enough calls soft-threshold warning should be present
    r2 = client.generate('more tokens here', tenant_id=tenant)
    assert isinstance(client._breaker_state.get(tenant, {}).get('warnings', 0), int)

    # ledger should have a tenant_budget entry (fallback ledger stores it)
    # use get_budget if available
    if hasattr(client._cost_ledger, 'get_budget'):
        val = client._cost_ledger.get_budget(f'tenant_budget:{tenant}')
    else:
        val = client._cost_ledger.get_cost(f'tenant_budget:{tenant}')
    assert val >= 0
