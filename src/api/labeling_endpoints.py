from __future__ import annotations
from fastapi import APIRouter, File, UploadFile, Request, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse
import csv, io, json
from typing import Optional
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(prefix='/api/v1/labeling', tags=['Labeling'])


@router.post('/import/csv', summary='Import labels via CSV')
async def import_csv(file: UploadFile = File(...), request: Request = None):
    """Accept CSV columns: decision_id,label,evidence,query_template,tenant_id,user_contacted,change_ticket_found,owner_confirmed,change_ticket"""
    text = await file.read()
    s = text.decode('utf-8', errors='ignore')
    reader = csv.DictReader(io.StringIO(s))
    inserted = 0
    errors = []
    try:
        from src.repositories import decision_labels_repo
    except Exception:
        raise HTTPException(status_code=500, detail='labels repo unavailable')
    for i, row in enumerate(reader):
        try:
            decision_id = row.get('decision_id') or row.get('decision')
            label = row.get('label')
            tenant = resolve_tenant_id(request, row.get('tenant_id') or row.get('tenant'))
            evidence = row.get('evidence')
            workflow = {
                'user_contacted': str(row.get('user_contacted') or '').strip().lower() in {'1', 'true', 'yes', 'y'},
                'change_ticket_found': str(row.get('change_ticket_found') or '').strip().lower() in {'1', 'true', 'yes', 'y'},
                'owner_confirmed': str(row.get('owner_confirmed') or '').strip().lower() in {'1', 'true', 'yes', 'y'},
                'change_ticket': row.get('change_ticket') or None,
            }
            if any(v for k, v in workflow.items() if k == 'change_ticket' or v):
                payload = {'workflow': workflow}
                if evidence:
                    payload['note'] = evidence
                evidence = json.dumps(payload, sort_keys=True)
            query_template = row.get('query_template')
            await decision_labels_repo.insert_label(None, decision_id, label, tenant, None, None, evidence, query_template)
            inserted += 1
        except Exception as e:
            errors.append({'row': i+1, 'error': str(e)})
    return {'ok': True, 'inserted': inserted, 'errors': errors}


@router.get('/export/csv', summary='Export labels as CSV')
async def export_csv(tenant_id: Optional[str] = None, request: Request = None):
    try:
        from src.db.database import fetch
    except Exception:
        raise HTTPException(status_code=500, detail='db unavailable')
    tenant_id = resolve_tenant_id(request, tenant_id)
    SQL = "SELECT event_id, decision_id, label, tenant_id, evidence, query_template, created_at FROM decision_labels WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL)) ORDER BY created_at DESC LIMIT 1000"
    try:
        rows = await fetch(SQL, tenant_id)
    except Exception:
        rows = []
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(['event_id','decision_id','label','tenant_id','evidence','query_template','created_at'])
    for r in rows:
        writer.writerow([r.get('event_id'), r.get('decision_id'), r.get('label'), r.get('tenant_id'), r.get('evidence'), r.get('query_template'), r.get('created_at')])
    out.seek(0)
    return StreamingResponse(iter([out.read()]), media_type='text/csv')


@router.get('/list', summary='List recent labels', operation_id='labeling_list_labels')
async def list_labels(tenant_id: Optional[str] = None, page: int = 1, page_size: int = 50, q: Optional[str] = None, sort_by: Optional[str] = 'created_at', sort_dir: Optional[str] = 'desc', request: Request = None):
    # Attempt to import DB fetch helper; if unavailable, fall back to empty results
    try:
        from src.db.database import fetch
    except Exception:
        async def fetch(*a, **k):
            return []

    # server-side pagination
    offset = max(0, (int(page) - 1)) * int(page_size)
    # Allow simple search q over decision_id, label, evidence
    where = "(tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL))"
    tenant_id = resolve_tenant_id(request, tenant_id)
    params = [tenant_id]
    if q:
        where = where + " AND (decision_id ILIKE $2 OR label ILIKE $2 OR evidence ILIKE $2)"
        params = [tenant_id, f"%{q}%"]
    # Validate sort_by
    if sort_by not in ('created_at','label','decision_id'):
        sort_by = 'created_at'
    sort_dir = str(sort_dir).lower()
    if sort_dir not in ('asc','desc'):
        sort_dir = 'desc'
    SQL = f"SELECT * FROM decision_labels WHERE {where} ORDER BY {sort_by} {sort_dir} LIMIT $%d OFFSET $%d" % (len(params)+1, len(params)+2)
    try:
        rows = await fetch(SQL, *params, int(page_size), offset)
    except Exception:
        rows = []
    # total count (best-effort)
    try:
        if q:
            cnt_sql = "SELECT count(1) as c FROM decision_labels WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL)) AND (decision_id ILIKE $2 OR label ILIKE $2 OR evidence ILIKE $2)"
            count_rows = await fetch(cnt_sql, tenant_id, f"%{q}%")
        else:
            count_rows = await fetch("SELECT count(1) as c FROM decision_labels WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL))", tenant_id)
        total = int(count_rows[0].get('c')) if count_rows else 0
    except Exception:
        total = 0
    return {'ok': True, 'rows': [dict(r) for r in rows], 'page': int(page), 'page_size': int(page_size), 'total': total}


@router.patch('/edit', summary='Edit an existing label (by id)')
async def edit_label(request: Request):
    """Accept JSON body or query params: {label_id: int, label?: str, evidence?: str, query_template?: str} """
    # Try JSON body first, fall back to query params for compatibility tests
    payload = {}
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        # build payload from query params
        try:
            payload = {k: v for k, v in request.query_params.items()}
        except Exception:
            payload = {}
    try:
        label_id = int(payload.get('label_id'))
    except Exception:
        raise HTTPException(status_code=400, detail='missing_label_id')
    try:
        from src.db.database import execute
        # best-effort update; only update provided fields
        sets = []
        params = []
        idx = 1
        if 'label' in payload and payload.get('label') is not None:
            sets.append(f"label=$%d" % idx); params.append(payload.get('label')); idx += 1
        if 'evidence' in payload and payload.get('evidence') is not None:
            sets.append(f"evidence=$%d" % idx); params.append(payload.get('evidence')); idx += 1
        if 'query_template' in payload and payload.get('query_template') is not None:
            sets.append(f"query_template=$%d" % idx); params.append(payload.get('query_template')); idx += 1
        if not sets:
            raise HTTPException(status_code=400, detail='no_fields')
        sql = "UPDATE decision_labels SET " + ",".join(sets) + " WHERE id=$%d" % idx
        params.append(label_id)
        await execute(sql, *params)
        return {'ok': True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/ui', response_class=HTMLResponse, include_in_schema=False)
async def ui():
    # Minimal analyst UI that posts CSV to /import/csv
    html = '''<!doctype html>
<html><head><title>Labeling Upload</title></head><body>
<h3>Upload labels CSV</h3>
<form id="f" enctype="multipart/form-data" method="post" action="/api/v1/labeling/import/csv">
  <input type="file" name="file" accept=".csv" />
  <button type="submit">Upload</button>
</form>
<p>CSV columns: decision_id,label,evidence,query_template,tenant_id,user_contacted,change_ticket_found,owner_confirmed,change_ticket</p>
</body></html>'''
    return HTMLResponse(content=html)


__all__ = ['router']
