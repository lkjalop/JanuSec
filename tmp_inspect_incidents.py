import importlib
import asyncio
m = importlib.import_module('src.api.server')
async def call():
    res = await m.list_incidents(request=None, limit=50, tenant_id=None)
    print('list_incidents returned count=', res.get('count'))
    incs = res.get('incidents') or []
    for i in incs[:10]:
        print('INC:', i)

asyncio.get_event_loop().run_until_complete(call())
