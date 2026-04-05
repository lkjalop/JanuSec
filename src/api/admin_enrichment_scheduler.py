from __future__ import annotations

import os, json
from fastapi import APIRouter, HTTPException, Depends
from src.security.roles import require_roles

router = APIRouter(prefix="/api/v1/admin/enrichment", tags=["admin"]) 


def _load_file_jobs():
    try:
        p = 'data/enrichment_jobs.json'
        if not os.path.exists(p):
            return []
        j = json.loads(open(p, 'r', encoding='utf-8').read() or '{}')
        out = []
        for k, v in j.items():
            rec = v.copy() if isinstance(v, dict) else {'next_run': v}
            rec['key'] = k
            out.append(rec)
        return out
    except Exception:
        return []


@router.get('/jobs')
def list_enrichment_jobs():
    # Prefer Redis-backed scheduler when enabled
    if os.getenv('ENABLE_REDIS_SCHEDULER','0').lower() in {'1','true','yes'}:
        try:
            # lazy import to avoid hard dependency
            from src.enrichment.redis_scheduler import get_global_scheduler
            import asyncio
            sched = asyncio.run(get_global_scheduler())
            if sched is not None:
                try:
                    jobs = asyncio.run(sched.list_jobs())
                    return {'source': 'redis', 'jobs': jobs}
                except Exception:
                    pass
        except Exception:
            pass
    # Fallback to file-backed jobs
    jobs = _load_file_jobs()
    return {'source': 'file', 'jobs': jobs}
