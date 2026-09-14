import pytest
from src.modules.endpoint_hunter import EndpointHunter

@pytest.mark.asyncio
async def test_lolbin_tfidf_basic(monkeypatch):
    hunter = EndpointHunter(config=None)
    # simulate multiple similar powershell commands to build df
    base_cmd = 'powershell.exe -nop -c echo hello'
    for i in range(5):
        ev = {'process': {'name': 'powershell.exe'}, 'cmdline': base_cmd + f' {i}'}
        await hunter.analyze_event(ev)
    # Now submit a rare token command
    rare_cmd = 'powershell.exe -nop -c invoke-randomartifactdownload xqzplatinum'
    ev_rare = {'process': {'name': 'powershell.exe'}, 'cmdline': rare_cmd}
    res = await hunter.analyze_event(ev_rare)
    assert any(f.startswith('endpoint:lolbin_cmd_tfidf') for f in res['factors']), res['factors']
    # Submit another common-looking command should not emit high rarity again
    ev_common = {'process': {'name': 'powershell.exe'}, 'cmdline': base_cmd + ' again'}
    res2 = await hunter.analyze_event(ev_common)
    # presence of rare factor second time is allowed but unlikely; we simply assert factors list returns
    assert 'endpoint:lolbin_cmd_tfidf_rare' not in res2['factors'], 'Rare factor repeated unexpectedly'
