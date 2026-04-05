import asyncio
import os
import json

from src.enrichment.redis_scheduler import get_global_scheduler

async def run_smoke():
    sched = await get_global_scheduler()
    if sched is None:
        print('redis scheduler unavailable')
        return 2
    # create a sample job
    await sched.schedule('smoke-job-1', {'hash': 'deadbeef', 'upstream': 'test'}, interval=1)
    # list jobs
    jobs = await sched.list_jobs()
    print('jobs:', jobs)
    # wait a bit to allow run_loop to execute if it's running externally
    return 0

if __name__ == '__main__':
    code = asyncio.run(run_smoke())
    print('exit', code)
    raise SystemExit(code)
