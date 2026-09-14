import asyncio

from modules.endpoint_hunter import EndpointHunter


async def test_rare_lineage_stabilization():
    eh = EndpointHunter(object())
    await eh.initialize()
    parent='p.exe'; child='c.exe'
    r1 = await eh.analyze_event({'process': {'name': child, 'parent_name': parent}})
    assert 'endpoint:rare_lineage' in r1['factors']
    for _ in range(4):
        await eh.analyze_event({'process': {'name': child, 'parent_name': parent}})
    r_last = await eh.analyze_event({'process': {'name': child, 'parent_name': parent}})
    assert 'endpoint:rare_lineage' not in r_last['factors']

async def test_exec_burst():
    eh = EndpointHunter(object())
    host='H1'
    for i in range(10):
        res = await eh.analyze_event({'host_id': host, 'process': {'name': f'p{i}', 'parent_name': 'init'}})
    assert any(f=='endpoint:exec_burst' for f in res['factors'])
