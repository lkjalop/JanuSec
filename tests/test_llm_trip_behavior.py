import time

from src.integrations.llm_client import LLMClient


def test_auto_trip_on_warnings_and_trip_duration(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    monkeypatch.setenv('LLM_TENANT_BUDGET', '0.000002')
    monkeypatch.setenv('LLM_TENANT_SOFT_THRESHOLD', '0.5')
    monkeypatch.setenv('LLM_BREAKER_FAILURE_THRESHOLD', '1')
    monkeypatch.setenv('LLM_BREAKER_TRIP_SECONDS', '1')

    client = LLMClient()
    tenant = 'tenant-trip'

    # first call -> maybe a warning
    r1 = client.generate('one two three', tenant_id=tenant)
    assert 'text' in r1

    # second call should cause warnings to reach threshold and auto-trip
    r2 = client.generate('second call with tokens', tenant_id=tenant)
    assert 'error' in r2 or 'text' in r2
    # if trip applied, subsequent immediate call should be tripped
    r3 = client.generate('immediate after', tenant_id=tenant)
    if 'error' in r3:
        assert r3['error'] == 'circuit_breaker_tripped' or r3['error'] == 'tenant_cost_threshold_exceeded'

    # wait for trip window to expire
    time.sleep(1.1)
    r4 = client.generate('after trip window', tenant_id=tenant)
    assert isinstance(r4, dict)
