from __future__ import annotations

import os
import time
import uuid
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile, Query
from src.api.runtime_state import get_server_runtime_state, persist_tenant_runtime
from src.domains.iam.correlation import correlate_events_time_window
from src.domains.iam.privilege_escalation import reevaluate_on_iam_event
import time

router = APIRouter(prefix='/api/v1/sandbox', tags=['Sandbox'])

_TASKS: dict[str, dict[str, Any]] = {}


def _enabled() -> bool:
    return os.getenv('SANDBOX_PROVIDER', '').strip() != '' and os.getenv('SANDBOX_API_URL', '') != ''


@router.post('/submit')
async def sandbox_submit(file: UploadFile | None = File(None), url: str | None = Query(None)):
    if not _enabled():
        raise HTTPException(status_code=503, detail='sandbox_disabled')
    if not file and not url:
        raise HTTPException(status_code=400, detail='file_or_url_required')
    task_id = str(uuid.uuid4())
    _TASKS[task_id] = {
        'task_id': task_id,
        'status': 'queued',
        'created_at': time.time(),
        'input': {'filename': getattr(file,'filename',None), 'url': url},
        'result': None
    }
    # For now, simulate immediate completion with normalized sample
    # Real implementation: POST to provider API then poll until finished
    _TASKS[task_id]['status'] = 'completed'
    _TASKS[task_id]['result'] = {
        'summary': 'Static analysis complete (simulated)'.strip(),
        'iocs': {'domains': [], 'ips': [], 'hashes': []},
        'mitre': ['T1059'],
        'factors': ['malware:suspicious_behavior']
    }
    # persist sandbox result into tenant runtime and trigger correlation
    try:
        tenant = Query(None)
    except Exception:
        tenant = None
    try:
        # if tenant query provided in URL, FastAPI would pass it; fallback to 'global'
        t = 'global'
        # Best-effort: use environment or leave global
        runtime = get_server_runtime_state(None)
        tmap = runtime.tenants.setdefault(t, {})
        rec = {'ts': time.time(), 'task_id': task_id, 'result': _TASKS[task_id]['result']}
        recent = tmap.setdefault('recent_sandbox_results', [])
        recent.append(rec)
        if len(recent) > 200:
            del recent[:-200]
        try:
            persist_tenant_runtime(runtime, t)
        except Exception:
            pass
        # correlate with IAM evals and trigger reevaluation when interesting factors found
        iam_events = tmap.get('iam_eval_results', [])
        if iam_events:
            correlated = correlate_events_time_window(iam_events, [rec], window_seconds=300)
            for c in correlated:
                try:
                    iam_ev = c.get('iam') or {}
                    reevaluate_on_iam_event(iam_ev, runtime=runtime, tenant_id=t)
                except Exception:
                    pass
            corr_store = tmap.setdefault('sandbox_iam_correlation', [])
            corr_store.extend(correlated)
            if len(corr_store) > 200:
                del corr_store[:-200]
    except Exception:
        pass
    return {'task_id': task_id, 'status': _TASKS[task_id]['status']}


@router.get('/result')
async def sandbox_result(task_id: str):
    if not _enabled():
        raise HTTPException(status_code=503, detail='sandbox_disabled')
    rec = _TASKS.get(task_id)
    if not rec:
        raise HTTPException(status_code=404, detail='task_not_found')
    return {
        'task_id': task_id,
        'status': rec.get('status'),
        'result': rec.get('result')
    }

__all__ = ['router']
