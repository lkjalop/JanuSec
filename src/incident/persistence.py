from __future__ import annotations

import os
import time
import json
import hashlib
from typing import Dict, Any

STORE_DIR = os.getenv('INCIDENT_STORE_DIR', 'data/incidents')
os.makedirs(STORE_DIR, exist_ok=True)


def incident_fingerprint(event: Dict[str, Any], keys=('dataset_id','event_id','host','user')) -> str:
    parts = []
    for k in keys:
        v = event.get(k)
        if v is None:
            continue
        parts.append(str(v))
    base = '|'.join(parts)
    h = hashlib.sha256(base.encode('utf-8')).hexdigest()
    return h


def _atomic_write(path: str, payload: Dict[str, Any]):
    tmp = path + '.tmp'
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(payload, f)
    os.replace(tmp, path)


def upsert_incident(payload: Dict[str, Any]) -> Dict[str, Any]:
    fp = incident_fingerprint(payload)
    path = os.path.join(STORE_DIR, f'{fp}.json')
    now = time.time()
    entry = {
        'fingerprint': fp,
        'first_seen': now,
        'last_seen': now,
        'count': 1,
        'payload': payload,
    }
    # if exists, merge simple counters
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                old = json.load(f)
            old['last_seen'] = now
            old['count'] = int(old.get('count',1)) + 1
            # merge payload minimally
            old['payload'] = payload
            _atomic_write(path, old)
            return old
        except Exception:
            pass
    _atomic_write(path, entry)
    return entry


def load_incident(fingerprint: str) -> Dict[str, Any] | None:
    path = os.path.join(STORE_DIR, f'{fingerprint}.json')
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None
