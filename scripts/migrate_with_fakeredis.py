import os
import asyncio
import json
from pathlib import Path

# Create a simple fake scheduler implementing schedule() and list_jobs()
class FakeScheduler:
    def __init__(self):
        self.jobs = {}
    async def schedule(self, key, payload, interval=3600):
        self.jobs[key] = {"payload": json.dumps(payload), "interval": interval, "next_run": 0}
    async def list_jobs(self):
        return [{"key": k, "data": v} for k, v in self.jobs.items()]

async def get_global_scheduler():
    return FakeScheduler()

# Monkeypatch import path for src.enrichment.redis_scheduler.get_global_scheduler
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Insert a fake module into sys.modules to satisfy import in migrate script
import types
fake_mod = types.ModuleType('src.enrichment.redis_scheduler')
setattr(fake_mod, 'get_global_scheduler', get_global_scheduler)
sys.modules['src.enrichment.redis_scheduler'] = fake_mod

# Ensure ENABLE_REDIS_SCHEDULER is set
os.environ['ENABLE_REDIS_SCHEDULER'] = '1'

# Run the migrate() from the script
import importlib
migrate_mod = importlib.import_module('scripts.migrate_enrichment_jobs_to_redis')

print('Running migration using FakeScheduler...')
res = migrate_mod.migrate()
print('migrated:', res)

# Show jobs from fake scheduler
loop = asyncio.new_event_loop()
async def show():
    sched = await get_global_scheduler()
    jobs = await sched.list_jobs()
    print('fake scheduler jobs count:', len(jobs))
    print(jobs)

loop.run_until_complete(show())
loop.close()
