# helper to run redis_scheduler_smoke_test.py with a fake get_global_scheduler
import sys, types, asyncio
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

async def get_global_scheduler():
    class S:
        def __init__(self):
            self.jobs = {}
        async def schedule(self,k,payload,interval=3600):
            self.jobs[k] = {'payload':payload,'interval':interval,'next_run':0}
        async def list_jobs(self):
            return [{'key':k,'data':v} for k,v in self.jobs.items()]
    return S()

fake = types.ModuleType('src.enrichment.redis_scheduler')
setattr(fake,'get_global_scheduler', get_global_scheduler)
import sys
sys.modules['src.enrichment.redis_scheduler'] = fake

# now run the smoke test
import runpy
runpy.run_path('scripts/redis_scheduler_smoke_test.py', run_name='__main__')
