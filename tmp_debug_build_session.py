import asyncio, traceback
from src.api.graph_sessions import build_session
payload = {'session_ids': ['batch-A'], 'correlate': True, 'ewma': False}
try:
    res = asyncio.run(build_session(payload=payload, request=None, runtime_override=None, args=None, kwargs=None, auth=None))
    print('build_session returned:', type(res))
except Exception as e:
    print('Exception calling build_session:')
    traceback.print_exc()
