import pytest
from modules.endpoint_hunter import EndpointHunter


@pytest.mark.asyncio
async def test_advanced_hunting_flag_off_suppresses_advanced(monkeypatch):
    monkeypatch.setenv('ADVANCED_ENDPOINT_HUNTING', '0')
    eh = EndpointHunter(object())
    # Event that only triggers advanced heuristics
    ev1 = {'function': 'DRSGetNCChanges'}
    res1 = await eh.analyze_event(ev1)
    assert 'endpoint:credential_access' not in res1['factors']

    ev2 = {'api_calls': ['VirtualAllocEx','WriteProcessMemory','CreateRemoteThread']}
    res2 = await eh.analyze_event(ev2)
    assert 'endpoint:process_injection' not in res2['factors']

    ev3 = {'encryption_type': 'rc4-hmac'}
    res3 = await eh.analyze_event(ev3)
    assert 'kerberos:encryption_downgrade' not in res3['factors']
