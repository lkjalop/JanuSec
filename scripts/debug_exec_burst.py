import asyncio
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.modules.endpoint_hunter import EndpointHunter

async def t():
    eh = EndpointHunter(object())
    host='H1'
    for i in range(10):
        res = await eh.analyze_event({'host_id': host, 'process': {'name': f'p{i}', 'parent_name': 'init'}})
        print(i, res)
        await asyncio.sleep(0)

if __name__ == '__main__':
    asyncio.run(t())
