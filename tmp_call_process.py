import os
os.environ['PYTEST_CURRENT_TEST']='1 (probe)'
import asyncio
from src.api.server import _process_endpoint_event, LogBatchContext, _RUNTIME
from src.api.server import LogEvent

BASE_EVENT = {'id':'e1','host':'h1','proc_name':'powershell.exe','parent_proc':'winword.exe','dest_ip':'9.9.9.9'}

async def runit():
    ctx = LogBatchContext(runtime=_RUNTIME, include_rules=True, classify=True, send_alerts=True, tenant_id=None, nx_enabled=False, dedup_ttl=1.0)
    processed, alert = await _process_endpoint_event(LogEvent(**BASE_EVENT), ctx)
    print('processed', processed)
    print('alert', alert)

asyncio.run(runit())
