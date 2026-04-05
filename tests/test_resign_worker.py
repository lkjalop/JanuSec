import os
import json
import tempfile
import shutil

from src.core import resign_worker


def _make_export_files(tmpdir, count=5):
    d = tmpdir / 'exports'
    d.mkdir()
    for i in range(count):
        p = d / f"rep_{i:03}.json"
        obj = {'token': f'tok{i}', 'events': [{'event_type': 'r', 'payload': '{}'}], 'key_id': 'old'}
        p.write_text(json.dumps(obj))
    return str(d)


def test_enqueue_and_process_fs(tmp_path, monkeypatch):
    # ensure no redis
    monkeypatch.delenv('RESIGN_JOBS_REDIS_URL', raising=False)
    monkeypatch.delenv('RATE_LIMIT_REDIS_URL', raising=False)
    exports_dir = _make_export_files(tmp_path, count=3)
    # enqueue job
    from src.core.arc_redis_queue import enqueue_job, pop_job, ack_job
    job = {'type': 'resign_exports', 'path_prefix': exports_dir, 'key_id': 'new-key-1', 'batch_size': 2}
    jid = enqueue_job(job)
    assert jid
    popped = pop_job(timeout=1)
    assert popped is not None
    job_obj, raw = popped
    # run process
    ok = resign_worker._process_job(job_obj)
    assert ok
