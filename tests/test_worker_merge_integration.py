import os
import json
from src.core.ingest.worker_service import process_single_job


def test_worker_process_single_job_merges(tmp_path, monkeypatch):
    # prepare upload file and sidecar
    upload_dir = tmp_path / 'uploads'
    upload_dir.mkdir()
    upload_file = upload_dir / 'bundle.txt'
    upload_file.write_text('C:\\Temp\\evil.exe\t133176576000000000 entry\n')
    sidecar = {'evil.exe': {'sha256': 'aa' * 32}}
    sidecar_path = upload_dir / 'bundle.json'
    sidecar_path.write_text(json.dumps(sidecar))

    # prepare job payload
    job = {'id': 'j1', 'payload': {'upload_path': str(upload_file)}}

    captured = {}

    def fake_process_event_batch(events, correlate=True):
        captured['events'] = list(events)
        return {'processed': len(captured['events'])}

    monkeypatch.setattr('src.core.ingest.ingest_worker.process_event_batch', fake_process_event_batch)

    res = process_single_job(job)
    assert res.get('processed', 0) >= 1
    events = captured.get('events', [])
    assert events
    # check merged hash present
    found = False
    for e in events:
        fp = e.get('file_path') or ''
        if os.path.basename(fp).lower() == 'evil.exe':
            assert 'hashes' in e and 'sha256' in e['hashes']
            found = True
    assert found
