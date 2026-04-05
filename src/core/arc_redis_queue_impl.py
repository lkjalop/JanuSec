import json
import os
import time
import uuid
from typing import Optional, Tuple


# Clean implementation used for local testing while original module is repaired.
_REDIS_URL = os.getenv('RESIGN_JOBS_REDIS_URL') or os.getenv('RATE_LIMIT_REDIS_URL')


def get_redis_client():
    if not _REDIS_URL:
        return None
    try:
        import redis
        rc = redis.from_url(_REDIS_URL)
        rc.ping()
        return rc
    except Exception:
        return None


def _fs_queue_dir() -> str:
    p = os.path.join('data', 'resign_jobs')
    os.makedirs(p, exist_ok=True)
    return p


def enqueue_job(job: dict) -> str:
    jid = job.get('job_id') or f"job-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    job['job_id'] = jid
    raw = json.dumps(job)
    rc = get_redis_client()
    if rc is not None:
        try:
            rc.rpush('resign:jobs', raw)
            rc.hset('resign:status', jid, json.dumps({'state': 'queued', 'created_ts': int(time.time())}))
            return jid
        except Exception:
            pass
    d = _fs_queue_dir()
    path = os.path.join(d, f"{jid}.json")
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(raw)
    with open(os.path.join(d, f"{jid}.status.json"), 'w', encoding='utf-8') as fh:
        fh.write(json.dumps({'state': 'queued', 'created_ts': int(time.time())}))
    return jid


def pop_job(timeout: int = 5) -> Optional[Tuple[dict, str]]:
    rc = get_redis_client()
    if rc is not None:
        try:
            res = rc.blpop('resign:jobs', timeout=timeout)
            if not res:
                return None
            _, raw = res
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8')
            return json.loads(raw), raw
        except Exception:
            pass
    d = _fs_queue_dir()
    files = [f for f in os.listdir(d) if f.endswith('.json') and not f.endswith('.status.json') and not f.endswith('.json.inprog')]
    files.sort()
    if not files:
        return None
    fn = files[0]
    path = os.path.join(d, fn)
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            raw = fh.read()
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        return None
    try:
        job = json.loads(raw)
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        return None
    inprog = path + '.inprog'
    try:
        os.rename(path, inprog)
    except Exception:
        pass
    return job, raw


def ack_job(payload_str: str):
    rc = get_redis_client()
    if rc is not None:
        return
    d = _fs_queue_dir()
    for fn in os.listdir(d):
        if not fn.endswith('.inprog'):
            continue
        path = os.path.join(d, fn)
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                if fh.read() == payload_str:
                    try:
                        os.remove(path)
                    except Exception:
                        pass
                    status_fp = os.path.join(d, fn.replace('.json.inprog', '.status.json'))
                    try:
                        os.remove(status_fp)
                    except Exception:
                        pass
                    return
        except Exception:
            continue


__all__ = ['enqueue_job', 'pop_job', 'ack_job', 'get_redis_client']
