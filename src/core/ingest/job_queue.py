import os
import json
import time
import uuid
from typing import Dict, Any, Optional

JOB_ROOT = os.getenv('JOB_QUEUE_DIR', os.path.join('data', 'jobs', 'kape'))
os.makedirs(JOB_ROOT, exist_ok=True)


def enqueue_job(payload: Dict[str, Any]) -> str:
    jid = str(uuid.uuid4())
    now = int(time.time())
    rec = {'id': jid, 'ts': now, 'payload': payload, 'status': 'queued'}
    path = os.path.join(JOB_ROOT, f"{now}_{jid}.json")
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(rec, fh)
    return jid


def list_jobs() -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    try:
        for fn in os.listdir(JOB_ROOT):
            try:
                p = os.path.join(JOB_ROOT, fn)
                with open(p, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                out[data.get('id')] = data
            except Exception:
                continue
    except Exception:
        pass
    return out


def dequeue_next_job() -> Optional[Dict[str, Any]]:
    # pick the oldest queued job; use a lock file to avoid races across workers
    entries = []
    for fn in os.listdir(JOB_ROOT):
        p = os.path.join(JOB_ROOT, fn)
        try:
            with open(p, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            entries.append((p, data))
        except Exception:
            continue
    entries.sort(key=lambda it: it[1].get('ts', 0))
    for p, data in entries:
        if data.get('status') == 'queued':
            # try to create a lock file next to job file
            lockfile = p + '.lock'
            try:
                fd = os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
            except FileExistsError:
                # someone else grabbed it
                continue
            except Exception:
                continue
            # mark as processing
            data['status'] = 'processing'
            data['started_at'] = int(time.time())
            try:
                with open(p, 'w', encoding='utf-8') as fh:
                    json.dump(data, fh)
            except Exception:
                try:
                    os.remove(lockfile)
                except Exception:
                    pass
            return data
    return None


def mark_job_complete(job_id: str, result: Dict[str, Any]) -> None:
    try:
        for fn in os.listdir(JOB_ROOT):
            p = os.path.join(JOB_ROOT, fn)
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                if data.get('id') == job_id:
                    data['status'] = 'done'
                    data['completed_at'] = int(time.time())
                    data['result'] = result
                    with open(p, 'w', encoding='utf-8') as fh2:
                        json.dump(data, fh2)
                    # remove any lockfile
                    try:
                        os.remove(p + '.lock')
                    except Exception:
                        pass
                    return
            except Exception:
                continue
    except Exception:
        pass
