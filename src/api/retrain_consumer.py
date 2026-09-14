from __future__ import annotations

import json
import time
import os
from typing import Any, Dict, List

from ..repositories import outbox_repo_sqlite as outbox_repo


def _ensure_training_dir() -> str:
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    p = os.path.join(repo, 'data', 'training')
    os.makedirs(p, exist_ok=True)
    return p


def consume_retrain_tasks(limit: int = 100) -> List[int]:
    """Consume pending outbox retrain tasks and append their payloads to an NDJSON training file.
    Returns list of processed outbox ids."""
    out = []
    now = int(time.time())
    td = _ensure_training_dir()
    fname = os.path.join(td, f'retrain_{now}.ndjson')
    tmp_fname = fname + '.tmp'

    rows = outbox_repo.next_pending(limit=limit)
    if not rows:
        return out

    # Write to a temp file and rename atomically to avoid partial writes
    try:
        with open(tmp_fname, 'a', encoding='utf-8') as fh:
            for r in rows:
                try:
                    payload = json.loads(r.get('payload_json') or '{}')
                except Exception:
                    payload = {'raw': r.get('payload_json')}
                fh.write(json.dumps(payload, ensure_ascii=False) + '\n')
                out.append(int(r.get('id')))
        try:
            os.replace(tmp_fname, fname)
        except Exception:
            # fallback to rename
            os.rename(tmp_fname, fname)
    finally:
        # cleanup tmp if still present
        try:
            if os.path.exists(tmp_fname):
                os.remove(tmp_fname)
        except Exception:
            pass

    # mark done
    for rid in out:
        try:
            outbox_repo.mark_done(rid)
        except Exception:
            continue

    return out


def cleanup_training_files(ttl_seconds: Optional[int] = None) -> None:
    """Remove training files older than TTL (seconds). TTL from env TRAINING_TTL_SECONDS."""
    try:
        if ttl_seconds is None:
            ttl_seconds = int(os.getenv('TRAINING_TTL_SECONDS', '0') or 0)
    except Exception:
        ttl_seconds = 0
    if not ttl_seconds or ttl_seconds <= 0:
        return
    td = _ensure_training_dir()
    now_ts = time.time()
    for fn in os.listdir(td):
        if not fn.endswith('.ndjson'):
            continue
        full = os.path.join(td, fn)
        try:
            m = os.path.getmtime(full)
            if (now_ts - m) > ttl_seconds:
                os.remove(full)
        except Exception:
            pass
