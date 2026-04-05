import asyncio
from src.api import graph_sessions
payload={'session_ids':['fixed-A-1','fixed-B-2','fixed-C-3'],'correlate':True,'ewma':False}
async def main():
    try:
        res=await graph_sessions.build_session(payload)
        print('OK', list(res.keys()))
    except Exception as exc:
        import traceback
        traceback.print_exc()
asyncio.run(main())
