import asyncio
from src.api.report_endpoints import reports_attention

async def run():
    resp = await reports_attention(limit=5)
    # Attempt to render JSONResponse content
    try:
        rendered = resp.render()
        if hasattr(rendered, '__await__'):
            rendered = await rendered
        if isinstance(rendered, (bytes, bytearray)):
            print(rendered.decode('utf-8'))
            return
        print(rendered)
        return
    except Exception as e:
        print('render error', e)
    print(type(resp), resp)

asyncio.get_event_loop().run_until_complete(run())

asyncio.get_event_loop().run_until_complete(run())
