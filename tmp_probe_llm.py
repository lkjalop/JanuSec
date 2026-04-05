from src.integrations import llm_client
import asyncio

print('DEFAULT_CLIENT type:', type(llm_client.DEFAULT_CLIENT))
client = llm_client.DEFAULT_CLIENT
try:
    if hasattr(client, 'generate'):
        coro = client.generate('test prompt', max_tokens=50)
        if asyncio.iscoroutine(coro):
            res = asyncio.get_event_loop().run_until_complete(coro)
        else:
            res = coro
        print('Generate result:', res)
    else:
        print('No generate method on client')
except Exception as e:
    import traceback
    traceback.print_exc()
    print('ERR', e)
