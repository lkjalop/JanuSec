import os
import json
import time
from threading import Thread
from src.core.ingest.job_queue import enqueue_job, JOB_ROOT
from src.core.ingest.job_queue import list_jobs
from src.core.ingest.worker_service import JobWorker


def test_persistent_worker_processes_job(tmp_path, monkeypatch):
    # prepare a fake data/uploads/kape bundle
    data_root = tmp_path / 'data'
    uploads = data_root / 'uploads' / 'kape' / 'bundle-persistent'
    uploads.mkdir(parents=True)
    upload_file = uploads / 'bundle.txt'
    upload_file.write_text('C:\\Temp\\evil.exe\t133176576000000000 entry\n')
    sidecar = {'evil.exe': {'sha256': 'aa' * 32}}
    (uploads / 'bundle.json').write_text(json.dumps(sidecar))

    # enqueue a job pointing to our temporary upload file
    payload = {'upload_path': str(upload_file)}
    jid = enqueue_job(payload)

    captured = {}

    def fake_process_event_batch(events, correlate=True):
        captured['events'] = list(events)
        return {'processed': len(captured['events'])}

    # monkeypatch the real process_event_batch in module namespace
    monkeypatch.setattr('src.core.ingest.ingest_worker.process_event_batch', fake_process_event_batch)

    # start a worker to process jobs; point JOB_ROOT to our temp JOB_ROOT location by creating a job file there
    # The enqueue_job used real JOB_ROOT; ensure job files are accessible by worker
    worker = JobWorker()
    worker.start()

    # wait for job to be processed with timeout
    timeout = time.time() + 5
    while time.time() < timeout:
        if captured.get('events'):
            break
        time.sleep(0.2)

    worker.stop()

    assert 'events' in captured
    found = False
    for e in captured['events']:
        if os.path.basename(e.get('file_path', '')).lower() == 'evil.exe':
            assert 'hashes' in e and 'sha256' in e['hashes']
            found = True
    assert found
