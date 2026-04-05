"""Migrate file-backed enrichment jobs (data/enrichment_jobs.json) into Redis scheduler.

Usage: set REDIS_URL and ENABLE_REDIS_SCHEDULER=1 then run this script.
"""
import os
import json
from pathlib import Path

JOB_FILE = Path('data') / 'enrichment_jobs.json'

def migrate():
    """Migrate file-backed jobs into Redis scheduler. Returns number migrated."""
    if os.getenv('ENABLE_REDIS_SCHEDULER','0').lower() not in {'1','true','yes'}:
        print('ENABLE_REDIS_SCHEDULER not set; aborting')
        return 0
    try:
        import asyncio
        from src.enrichment.redis_scheduler import get_global_scheduler
    except Exception as e:
        print('redis scheduler not available:', e)
        return 0

    if not JOB_FILE.exists():
        print('No', JOB_FILE)
        return 0

    j = json.loads(JOB_FILE.read_text(encoding='utf-8') or '{}')

    async def _run():
        sched = await get_global_scheduler()
        if sched is None:
            print('Scheduler not available')
            return 0
        migrated = 0
        for k, v in j.items():
            try:
                payload = json.loads(v.get('payload','{}')) if isinstance(v.get('payload'), str) else v.get('payload')
                interval = int(v.get('interval', 3600) or 3600)
                await sched.schedule(k, payload or {}, interval=interval)
                migrated += 1
            except Exception:
                pass
        return migrated

    try:
        return int(asyncio.run(_run()) or 0)
    except Exception as e:
        print('migration failed', e)
        return 0


if __name__ == '__main__':
    n = migrate()
    print('migrated', n)
