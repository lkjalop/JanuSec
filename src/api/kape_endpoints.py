from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
import os
import time
from src.core.malware.evidence import build_evidence_bundle, persist_bundle
from src.core.malware.static_runner import run_static_analysis

from src.core.ingest.kape_parser import normalize_kape_stream
from src.core.ingest.ingest_worker import process_event_batch
from src.core.ingest.job_queue import enqueue_job

router = APIRouter(prefix='/api/v1/kape', tags=['kape'])


@router.post('/upload')
async def upload_kape_bundle(background: BackgroundTasks, file: UploadFile = File(...), async_process: bool = False, trigger_sandbox: bool = False):
    uploads_dir = os.getenv('KAPE_UPLOAD_DIR', os.path.join('data', 'uploads', 'kape'))
    os.makedirs(uploads_dir, exist_ok=True)
    ts = int(time.time())
    fname = f"{ts}_{file.filename}"
    dest = os.path.join(uploads_dir, fname)
    try:
        data = await file.read()
        with open(dest, 'wb') as fh:
            fh.write(data)
        text = data.decode('utf-8', errors='ignore').splitlines()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_upload')

    events = list(normalize_kape_stream(text))

    if async_process:
        try:
            job_payload = {'upload_path': dest, 'timestamp': time.time(), 'filename': file.filename}
            job_id = enqueue_job(job_payload)
        except Exception:
            job_id = None
        forwarded = 0
    else:
        try:
            res = process_event_batch(events, correlate=True)
            forwarded = res.get('processed', 0) if isinstance(res, dict) else 0
        except Exception:
            forwarded = 0

    if trigger_sandbox:
        try:
            sample_info = {'filename': file.filename, 'path': dest, 'size': len(data)}
            bundle = build_evidence_bundle(sample_info, initiated_by='kape_upload')
            try:
                bundle['static'] = run_static_analysis(dest)
                bundle.setdefault('logs', []).append({'ts': time.time(), 'msg': 'static_analysis_complete'})
            except Exception:
                bundle.setdefault('logs', []).append({'ts': time.time(), 'msg': 'static_analysis_failed'})
            persist_bundle(bundle)
        except Exception:
            pass

    resp = {'processed': len(events), 'forwarded': forwarded, 'sessions': []}
    if async_process:
        resp['job_id'] = job_id
    return resp
from typing import List
