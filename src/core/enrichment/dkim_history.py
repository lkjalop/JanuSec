import os
import json
import time
import tempfile
from threading import RLock
from typing import Optional, Dict, Any

_LOCK = RLock()
_CACHE: Dict[str, Dict[str, Any]] = {}

def _path() -> str:
    return os.getenv('DKIM_HISTORY_PATH', os.path.join('data', 'dkim_history.json'))

def _ttl() -> int:
    try:
        return int(os.getenv('DKIM_HISTORY_TTL_SECONDS', str(30*24*3600)))
    except Exception:
        return 30*24*3600

def _load_all() -> Dict[str, Dict[str, Any]]:
    p = _path()
    try:
        if p in _CACHE:
            entry = _CACHE[p]
            if entry.get('expires_at', 0) > time.time():
                return entry.get('data', {})
        if not os.path.exists(p):
            _CACHE[p] = {'data': {}, 'expires_at': time.time() + 5}
            return {}
        with open(p, 'r', encoding='utf-8') as fh:
            data = json.load(fh) or {}
        _CACHE[p] = {'data': data, 'expires_at': time.time() + 5}
        return data
    except Exception:
        return {}

def _atomic_write(p: str, data: Dict[str, Any]) -> None:
    try:
        d = os.path.dirname(p) or '.'
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh)
        os.replace(tmp, p)
    except Exception:
        # best-effort: try non-atomic write
        try:
            with open(p, 'w', encoding='utf-8') as fh:
                json.dump(data, fh)
        except Exception:
            pass

def get_last_dkim(from_address: str) -> Optional[Dict[str, Any]]:
    """Return the last DKIM record for `from_address`, or None.

    Record shape: {'valid': bool, 'signing_domain': str|None, 'ts': float}
    """
    if not from_address:
        return None
    key = from_address.strip().lower()
    with _LOCK:
        data = _load_all()
        entry = data.get(key)
        if not entry:
            return None
        # check TTL
        ts = entry.get('ts', 0)
        if ts and (_ttl() > 0) and (time.time() - ts) > _ttl():
            # expired
            try:
                del data[key]
                _atomic_write(_path(), data)
            except Exception:
                pass
            return None
        return entry

def record_dkim_result(from_address: str, valid: bool, signing_domain: Optional[str] = None, ts: Optional[float] = None) -> None:
    """Record a DKIM verification result for `from_address`.

    Overwrites previous entry for that address.
    """
    if not from_address:
        return
    key = from_address.strip().lower()
    now = ts or time.time()
    entry = {'valid': bool(valid), 'signing_domain': signing_domain, 'ts': now}
    p = _path()
    with _LOCK:
        data = _load_all()
        data[key] = entry
        try:
            _atomic_write(p, data)
            # refresh cache
            _CACHE[p] = {'data': data, 'expires_at': time.time() + 5}
        except Exception:
            pass


def compact_history(max_entries: int = 5000) -> None:
    """Remove expired entries and ensure total entries <= max_entries.

    Keeps the most recent entries by timestamp when trimming.
    """
    p = _path()
    with _LOCK:
        data = _load_all()
        ttl = _ttl()
        now = time.time()
        # remove expired
        keys_to_delete = []
        for k, v in list(data.items()):
            ts = v.get('ts', 0)
            if ttl > 0 and ts and (now - ts) > ttl:
                keys_to_delete.append(k)
        for k in keys_to_delete:
            try:
                del data[k]
            except Exception:
                pass
        # trim by size
        if len(data) > max_entries:
            ordered = sorted(data.items(), key=lambda kv: kv[1].get('ts', 0), reverse=True)
            keep = dict(ordered[:max_entries])
            data = keep
        try:
            _atomic_write(p, data)
            _CACHE[p] = {'data': data, 'expires_at': time.time() + 5}
        except Exception:
            pass

__all__ = ['get_last_dkim', 'record_dkim_result']
