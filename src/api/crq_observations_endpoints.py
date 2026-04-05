from __future__ import annotations

import os, json
from fastapi import APIRouter, Query, HTTPException, Header
from pydantic import BaseModel
import time
from fastapi.responses import StreamingResponse
import io, csv

router = APIRouter(prefix="/api/v1/crq", tags=["crq"])


@router.get('/recent')
def recent_observations(limit: int = Query(50, ge=1, le=100), tenant: str | None = None):
    p = os.path.join('data', 'crq_shadow.json')
    try:
        if not os.path.exists(p):
            return {'observations': []}
        data = json.loads(open(p, 'r', encoding='utf-8').read() or '[]')
        if tenant:
            data = [d for d in data if d.get('tenant') == tenant]
        # return most recent `limit` by ts if present
        try:
            data = sorted(data, key=lambda x: x.get('ts', 0), reverse=True)
        except Exception:
            pass
        return {'observations': data[:limit]}
    except Exception:
        return {'observations': []}



class LabelPayload(BaseModel):
    obs_id: str
    label: str  # 'tp' | 'fp' | 'undetermined'
    annotator: str | None = None
    notes: str | None = None


@router.post('/label')
def label_observation(payload: LabelPayload, x_role: str | None = Header(None)):
    # require analyst role for labeling
    if (x_role or '').lower() != 'analyst':
        raise HTTPException(status_code=403, detail='forbidden')
    p = os.path.join('data', 'crq_labels.json')
    try:
        os.makedirs(os.path.dirname(p) or 'data', exist_ok=True)
        labels = json.loads(open(p, 'r', encoding='utf-8').read() or '[]')
    except Exception:
        labels = []
    rec = payload.dict()
    rec['ts'] = int(time.time())
    labels.append(rec)
    try:
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(labels, ensure_ascii=False))
    except Exception:
        raise HTTPException(status_code=500, detail='persist_failed')
    return {'status': 'ok', 'record': rec}



@router.get('/labels')
def list_labels():
    p = os.path.join('data', 'crq_labels.json')
    try:
        if not os.path.exists(p):
            return {'labels': []}
        labels = json.loads(open(p, 'r', encoding='utf-8').read() or '[]')
        # return most recent first
        try:
            labels = sorted(labels, key=lambda x: x.get('ts', 0), reverse=True)
        except Exception:
            pass
        return {'labels': labels}
    except Exception:
        return {'labels': []}


@router.get('/labels/export')
def export_labels():
    p = os.path.join('data', 'crq_labels.json')
    try:
        if not os.path.exists(p):
            return {'labels': []}
        labels = json.loads(open(p, 'r', encoding='utf-8').read() or '[]')
    except Exception:
        labels = []
    # stream CSV
    def iter_csv():
        fh = io.StringIO()
        w = csv.writer(fh)
        w.writerow(['obs_id', 'label', 'annotator', 'ts', 'notes'])
        yield fh.getvalue()
        fh.truncate(0); fh.seek(0)
        for r in labels:
            w.writerow([r.get('obs_id'), r.get('label'), r.get('annotator'), r.get('ts'), r.get('notes')])
            yield fh.getvalue()
            fh.truncate(0); fh.seek(0)
    return StreamingResponse(iter_csv(), media_type='text/csv')
