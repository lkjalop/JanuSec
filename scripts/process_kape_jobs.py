#!/usr/bin/env python3
import time
from src.core.ingest.job_queue import dequeue_next_job, mark_job_complete
from src.core.ingest.ingest_worker import process_event_batch
import os, json

print('KAPE job worker starting...')
while True:
    job = dequeue_next_job()
    if not job:
        time.sleep(1)
        continue
    jid = job.get('id')
    payload = job.get('payload', {})
    upload_path = payload.get('upload_path')
    print('Processing job', jid, 'path', upload_path)
    result = {'processed': 0, 'error': None}
    try:
        if upload_path and os.path.exists(upload_path):
            with open(upload_path, 'rb') as fh:
                data = fh.read()
            try:
                text = data.decode('utf-8', errors='ignore').splitlines()
                events = list(__import__('src.core.ingest.kape_parser', fromlist=['normalize_kape_stream']).normalize_kape_stream(text))
                res = process_event_batch(events, correlate=True)
                result['processed'] = res.get('processed', 0) if isinstance(res, dict) else 0
            except Exception as e:
                result['error'] = str(e)
        else:
            result['error'] = 'upload_missing'
    except Exception as e:
        result['error'] = str(e)
    mark_job_complete(jid, result)
    print('Job', jid, 'done', result)
    time.sleep(0.1)
