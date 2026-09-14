import asyncio
import time
import threading
import os
from typing import Optional
from src.core.ingest.job_queue import dequeue_next_job, mark_job_complete
from src.core.ingest.hash_merge import merge_hashes


def process_single_job(job: dict) -> dict:
    jid = job.get('id')
    payload = job.get('payload') or {}
    upload_path = payload.get('upload_path')
    result = {'processed': 0, 'error': None}
    try:
        if upload_path:
            with open(upload_path, 'rb') as fh:
                data = fh.read()
            text = data.decode('utf-8', errors='ignore').splitlines()
            from src.core.ingest.kape_parser import normalize_kape_stream, _load_sidecar_hashes_for_path
            events = list(normalize_kape_stream(text))
            # attempt to load sidecar hashes from upload basepath + '.json'
            sidecar_map = {}
            try:
                sidecar_map = _load_sidecar_hashes_for_path(os.path.splitext(upload_path)[0])
            except Exception:
                sidecar_map = {}
            # normalize sidecar keys to lowercase for robust matching
            if sidecar_map:
                norm_sidecar = {}
                for k, v in sidecar_map.items():
                    if not isinstance(k, str):
                        continue
                    norm_sidecar[k.lower()] = v
                    # also add basename key if path-like
                    try:
                        bn = os.path.basename(k).lower()
                        if bn and bn not in norm_sidecar:
                            norm_sidecar[bn] = v
                    except Exception:
                        pass
                for ev in events:
                    fp = ev.get('file_path') or ev.get('file') or None
                    if not fp or not isinstance(fp, str):
                        continue
                    lookup_keys = [fp.lower(), os.path.basename(fp).lower()]
                    side = None
                    for lk in lookup_keys:
                        if lk in norm_sidecar:
                            side = norm_sidecar.get(lk)
                            break
                    if side:
                        hv = ev.get('hashes') or {}
                        ev['hashes'] = merge_hashes(hv, side)
            from src.core.ingest.ingest_worker import process_event_batch
            res = process_event_batch(events, correlate=True)
            result['processed'] = res.get('processed', 0) if isinstance(res, dict) else 0
        else:
            result['error'] = 'upload_missing'
    except Exception as e:
        result['error'] = str(e)
    return result


def worker_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        job = dequeue_next_job()
        if not job:
            time.sleep(0.5)
            continue
        jid = job.get('id')
        res = process_single_job(job)
        mark_job_complete(jid, res)


class JobWorker:
    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=worker_loop, args=(self._stop,), daemon=True)
        self._thread.start()

    def stop(self):
        if not self._thread:
            return
        self._stop.set()
        self._thread.join(timeout=2)


_GLOBAL_WORKER: Optional[JobWorker] = None


def start_global_worker():
    global _GLOBAL_WORKER
    if _GLOBAL_WORKER is None:
        _GLOBAL_WORKER = JobWorker()
        _GLOBAL_WORKER.start()


def stop_global_worker():
    global _GLOBAL_WORKER
    if _GLOBAL_WORKER is not None:
        _GLOBAL_WORKER.stop()
        _GLOBAL_WORKER = None
