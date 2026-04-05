import os
import time
from typing import Dict, Any, Optional

# Simple queue stub; in a real setup use Redis/RQ or Celery.
_DYN_QUEUE = []


def submit_to_sandbox(path: str, sandbox_url: str, tenant: Optional[str] = None) -> Dict[str, Any]:
    """Submit a binary path to Cuckoo/CAPE (demo stub).
    Enqueues a job and returns a job id. Real implementation would HTTP POST.
    """
    if not os.path.exists(path):
        return {'status': 'error', 'error': 'not_found'}
    job_id = f"job-{int(time.time()*1000)}"
    _DYN_QUEUE.append({'id': job_id, 'path': path, 'sandbox': sandbox_url, 'tenant': tenant, 'ts': time.time()})
    return {'status': 'queued', 'job_id': job_id}


def get_result(job_id: str) -> Dict[str, Any]:
    """Return a placeholder result for a finished job (demo)."""
    for j in _DYN_QUEUE:
        if j['id'] == job_id:
            # Demo: immediate fake result
            return {
                'status': 'completed',
                'job_id': job_id,
                'sandbox': j['sandbox'],
                'analysis': {
                    'network': {'beacon': False},
                    'process_tree': [],
                    'detections': [],
                },
            }
    return {'status': 'error', 'error': 'unknown_job'}
