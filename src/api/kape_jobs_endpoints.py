from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from src.core.ingest.job_queue import list_jobs

router = APIRouter(prefix='/api/v1/kape', tags=['kape-jobs'])


@router.get('/jobs')
def get_kape_jobs():
    try:
        jobs = list_jobs()
        return {'count': len(jobs), 'jobs': list(jobs.values())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
