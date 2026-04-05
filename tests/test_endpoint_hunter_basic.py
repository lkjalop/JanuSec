import pytest

from src.modules.endpoint_hunter import EndpointHunter


def test_rare_lineage_basic():
    eh = EndpointHunter(object())
    # New parent->child pair should be considered rare
    ev = {'process': {'name': 'suspicious.exe', 'parent_name': 'unknownparent.exe'}}
    res = pytest.run(asyncio=False, func=lambda: None) if False else None
    # Use analyze_event synchronously via asyncio run (tests marked sync)
    import asyncio
    r = asyncio.get_event_loop().run_until_complete(eh.analyze_event(ev))
    assert 'endpoint:rare_lineage' in r['factors']


def test_cumulative_delta_cap():
    eh = EndpointHunter(object())
    # Craft an event that triggers many heuristics to push delta sum above cap
    ev = {
        'process': {'name': 'evil.exe', 'parent_name': 'unknownparent.exe'},
        'host_id': 'h1',
        'cmdline': 'rundll32 x.dll,Start procdump -ma lsass',
        'registry_path': 'software\\microsoft\\windows\\currentversion\\run',
        'api_calls': ['VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','SetThreadContext']
    }
    import asyncio
    r = asyncio.get_event_loop().run_until_complete(eh.analyze_event(ev))
    # total delta must be <= 0.15 as enforced by cap
    assert r['confidence_delta'] <= 0.15
