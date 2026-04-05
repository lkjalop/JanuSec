from __future__ import annotations

import os
import json
import time
from fastapi import APIRouter, HTTPException, Request
from src.security.roles import require_roles

router = APIRouter(prefix="/api/v1/assessments", tags=["assessments"])


@router.post('/save_metadata')
@require_roles('analyst','admin')
async def save_assessment_metadata(request: Request):
    payload = await request.json()
    org = (payload.get('org') or 'unknown').strip() or 'unknown'
    ts = int(payload.get('ts') or time.time())
    # Build path: data/assessments/{org}/{YYYYMMDD}/metadata_{ts}.json
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    datepart = time.strftime('%Y%m%d', time.gmtime(ts))
    dest_dir = os.path.join(repo_root, 'data', 'assessments', org, datepart)
    try:
        os.makedirs(dest_dir, exist_ok=True)
        fname = os.path.join(dest_dir, f'metadata_{ts}.json')
        with open(fname, 'w', encoding='utf-8') as fh:
            json.dump({'saved_at': time.time(), 'payload': payload}, fh, indent=2)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'failed to persist metadata: {exc}')
    return {'ok': True, 'path': fname}


@router.post('/report/{report_id}/flag_for_retrain')
async def flag_for_retrain(report_id: str, request: Request):
    """Lightweight endpoint to flag a report row for retraining.

    Accepts query param `row_id` and enqueues a retrain task into the
    durable outbox when available, else into the in-memory retrain queue.
    """
    row_id = request.query_params.get('row_id') or request.query_params.get('row')
    if not row_id:
        raise HTTPException(status_code=400, detail='missing_row_id')
    # locate report on disk
    try:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        datepart = time.strftime('%Y%m%d', time.gmtime(time.time()))
        path = os.path.join(repo_root, 'data', 'assessments', 'unknown', datepart, 'reports', f'{report_id}.json')
        if not os.path.exists(path):
            return {'detail': 'not_found'}
        with open(path, 'r', encoding='utf-8') as fh:
            obj = json.load(fh)
    except Exception:
        raise HTTPException(status_code=500, detail='read_failed')
    # find row
    rows = obj.get('per_row') or obj.get('rows') or []
    target = None
    for r in rows:
        try:
            if (r.get('row_id') or r.get('id') or r.get('row')) == row_id:
                target = r
                break
        except Exception:
            continue
    if not target:
        return {'detail': 'row_not_found'}
    payload = {'report_id': report_id, 'row_id': row_id, 'payload': target}
    # try durable outbox first
    try:
        from src.repositories.outbox_repo_sqlite import enqueue as _enqueue
        rid = _enqueue('retrain', obj.get('org') or 'unknown', row_id, payload)
        return {'ok': True, 'outbox_id': rid}
    except Exception:
        try:
            from src.ml.retrain import enqueue_labels
            enqueue_labels([payload])
            return {'ok': True}
        except Exception:
            raise HTTPException(status_code=500, detail='enqueue_failed')


@router.post('/admin/consume_retrain')
async def admin_consume_retrain(request: Request):
    """Admin/test helper: consume retrain outbox tasks and write NDJSON training files."""
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    admin_key = os.getenv('ADMIN_API_KEY')
    if not (os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or (api_key and admin_key and api_key == admin_key)):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    limit = int(payload.get('limit') or 10)
    try:
        from src.api.retrain_consumer import consume_retrain_tasks
        processed = consume_retrain_tasks(limit=limit)
        return {'ok': True, 'processed_ids': processed}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'consume_failed:{e}')


@router.post('/feedback')
async def capture_feedback_simple(request: Request):
    """Lightweight feedback capture endpoint for tests and simple integrations.

    Accepts a JSON payload and persists via the reporting feedback helper.
    Does not enforce roles to keep test wiring simple.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    if not payload:
        raise HTTPException(status_code=400, detail='missing_payload')
    try:
        from src.reporting.feedback_capture import persist_feedback
    except Exception:
        raise HTTPException(status_code=500, detail='feedback_module_unavailable')
    ok = persist_feedback(payload)
    if not ok:
        raise HTTPException(status_code=500, detail='persist_failed')
    return {'ok': True, 'stored': ok}
