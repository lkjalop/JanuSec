from pathlib import Path
import sys
import types
import asyncio

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Create fake redis_scheduler module with get_global_scheduler returning a scheduler with list_jobs()
async def get_global_scheduler():
    class Sched:
        async def list_jobs(self):
            return [{'key':'job1','data':{'payload':'{}','interval':'60','next_run':'0'}}, {'key':'job2','data':{'payload':'{}','interval':'3600','next_run':'0'}}]
    return Sched()

fake_mod = types.ModuleType('src.enrichment.redis_scheduler')
setattr(fake_mod, 'get_global_scheduler', get_global_scheduler)
sys.modules['src.enrichment.redis_scheduler'] = fake_mod

# Set env to enable redis path in admin endpoint
import os
os.environ['ENABLE_REDIS_SCHEDULER'] = '1'

from fastapi import FastAPI
from fastapi.testclient import TestClient
import importlib

crq = importlib.import_module('src.api.crq_observations_endpoints')
jobs = importlib.import_module('src.api.admin_enrichment_scheduler')

app = FastAPI()
app.include_router(crq.router)
app.include_router(jobs.router)

client = TestClient(app)
print('CRQ status', client.get('/api/v1/crq/recent').status_code)
resp = client.get('/api/v1/admin/enrichment/jobs')
print('Jobs status', resp.status_code)
print('Jobs json', resp.json())
