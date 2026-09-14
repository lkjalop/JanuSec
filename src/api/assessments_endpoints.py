from __future__ import annotations

from src.security.storage_paths import storage_path
from src.api.tenant_helpers import resolve_tenant_id
from src.api.report_endpoints import _load_persisted_assessment_report_data

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
    org = resolve_tenant_id(request, payload.get('org'))
    if not org:
        raise HTTPException(status_code=400, detail='tenant_id_required')
    ts = int(payload.get('ts') or time.time())
    # Build path: data/assessments/{org}/{YYYYMMDD}/metadata_{ts}.json
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    datepart = time.strftime('%Y%m%d', time.gmtime(ts))
    dest_dir = storage_path(storage_path(os.path.join(repo_root, 'data', 'assessments'), org), datepart)
    try:
        os.makedirs(dest_dir, exist_ok=True)
        fname = storage_path(dest_dir, f'metadata_{ts}.json')
        with open(fname, 'w', encoding='utf-8') as fh:
            json.dump({'saved_at': time.time(), 'payload': payload}, fh, indent=2)
    except Exception as exc:
        raise HTTPException(status_code=500, detail='metadata_persistence_failed')
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
    tenant = resolve_tenant_id(request)
    _, obj = _load_persisted_assessment_report_data(report_id, tenant)
    if not obj:
        raise HTTPException(status_code=404, detail='assessment_not_found')
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


@router.get('/{assessment_id}/iocs')
async def export_iocs(assessment_id: str, request: Request):
    """Phase-1 IOC export: return deduplicated, cutoff-filtered IOCs for an assessment.

    Query params:
        format: 'json' (default) or 'stix' for a minimal STIX 2.1 bundle
    """
    import uuid as _uuid
    fmt = (request.query_params.get('format') or 'json').lower()
    tenant = resolve_tenant_id(request)
    _, assessment_obj = _load_persisted_assessment_report_data(assessment_id, tenant)
    if not assessment_obj:
        raise HTTPException(status_code=404, detail='assessment_not_found')
    raw_rows = assessment_obj.get('raw_rows') or assessment_obj.get('per_row') or assessment_obj.get('rows') or []

    try:
        from src.reporting.adapters.csv_adapter import _collect_iocs_from_rows
        iocs = _collect_iocs_from_rows(raw_rows)
    except Exception as exc:
        raise HTTPException(status_code=500, detail='ioc_extraction_failed')

    generated_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    if fmt == 'stix':
        # Minimal STIX 2.1 bundle — indicators only
        objects: list[dict] = []
        for ip in (iocs.get('public_ips') or iocs.get('ips') or []):
            objects.append({
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f"indicator--{_uuid.uuid5(_uuid.NAMESPACE_URL, ip)}",
                'created': generated_at,
                'modified': generated_at,
                'name': ip,
                'pattern': f"[ipv4-addr:value = '{ip}']",
                'pattern_type': 'stix',
                'indicator_types': ['malicious-activity'],
                'valid_from': generated_at,
            })
        for dom in (iocs.get('domains') or []):
            objects.append({
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f"indicator--{_uuid.uuid5(_uuid.NAMESPACE_URL, dom)}",
                'created': generated_at,
                'modified': generated_at,
                'name': dom,
                'pattern': f"[domain-name:value = '{dom}']",
                'pattern_type': 'stix',
                'indicator_types': ['malicious-activity'],
                'valid_from': generated_at,
            })
        for sha in (iocs.get('hashes') or []):
            objects.append({
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f"indicator--{_uuid.uuid5(_uuid.NAMESPACE_URL, sha)}",
                'created': generated_at,
                'modified': generated_at,
                'name': sha,
                'pattern': f"[file:hashes.'SHA-256' = '{sha}']",
                'pattern_type': 'stix',
                'indicator_types': ['malicious-activity'],
                'valid_from': generated_at,
            })
        return {
            'type': 'bundle',
            'id': f"bundle--{_uuid.uuid4()}",
            'spec_version': '2.1',
            'created': generated_at,
            'objects': objects,
        }

    # Default: JSON format
    return {
        'assessment_id': assessment_id,
        'generated_at': generated_at,
        'ioc_cutoffs_days': {'ips': 60, 'domains': 30, 'hashes': 'never', 'processes': 90},
        'iocs': {
            'ips':       iocs.get('ips') or [],
            'public_ips': iocs.get('public_ips') or [],
            'domains':   iocs.get('domains') or [],
            'hashes':    iocs.get('hashes') or [],
            'processes': iocs.get('processes') or [],
        },
    }
