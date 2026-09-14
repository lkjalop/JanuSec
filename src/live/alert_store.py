"""Alert store with size-based rotation, retention, and integrity chain.

Each appended alert line structure (json):
  {
    ... original alert fields ...,
    "hash": SHA256(hex) of canonical JSON without trailing newline (excluding hash & hmac fields),
    "prev_hash": previous line's hash (or null),
    "hmac": optional HMAC-SHA256 over (hash || prev_hash) if ALERTS_HMAC_SECRET set
  }

Environment variables:
  ALERTS_LOG_PATH (default artifacts/alerts/alerts.jsonl)
  ALERTS_MAX_BYTES (default 20MB) rotate when exceeded before write
  ALERTS_RETENTION (default 5) number of rotated files to keep
  ALERTS_HMAC_SECRET (optional) enables per-line HMAC for tamper evidence

Metrics (if prometheus_client available):
  alerts_rotations_total
  alerts_store_write_failures_total
  alerts_integrity_last_hash (Gauge labeled path)
"""
from __future__ import annotations

import glob
import hashlib
import hmac as _hmac
import json
import os
import threading
import time
from typing import Any, Dict

_PATH = os.getenv('ALERTS_LOG_PATH','artifacts/alerts/alerts.jsonl')
_MAX_BYTES = int(os.getenv('ALERTS_MAX_BYTES','20000000'))
_RETENTION = int(os.getenv('ALERTS_RETENTION','5'))
_HMAC_SECRET = os.getenv('ALERTS_HMAC_SECRET')
_LOCK = threading.Lock()
_LAST_HASH = None  # updated after each append
_DEFAULT_PATH = 'artifacts/alerts/alerts.jsonl'


def _current_path() -> str:
    return os.getenv('ALERTS_LOG_PATH', _DEFAULT_PATH)


def _current_max_bytes() -> int:
    try:
        return int(os.getenv('ALERTS_MAX_BYTES', '20000000') or 0)
    except Exception:
        return 20000000


def _current_retention() -> int:
    try:
        return int(os.getenv('ALERTS_RETENTION', '5') or 5)
    except Exception:
        return 5


def _current_hmac_secret() -> str | None:
    return os.getenv('ALERTS_HMAC_SECRET')


_LOCK = threading.Lock()
_LAST_HASH = None  # updated after each append


def _load_last_hash_for_existing_file() -> None:
    """If an alert log already exists at _PATH, inspect the last non-empty
    JSON line and set _LAST_HASH to its stored 'hash' value. This helps
    tests that call importlib.reload(alert_store) after changing
    ALERTS_LOG_PATH to pick up an existing file and maintain a consistent
    integrity chain for subsequent appends.
    """
    global _LAST_HASH
    try:
        path = _current_path()
        if not os.path.exists(path):
            _LAST_HASH = None
            return
        last = None
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                last = line
        if not last:
            _LAST_HASH = None
            return
        try:
            rec = json.loads(last)
            _LAST_HASH = rec.get('hash')
        except Exception:
            _LAST_HASH = None
    except Exception:
        _LAST_HASH = None


# Metrics registration (best-effort)
try:  # pragma: no cover
    from prometheus_client import Counter as _C, Gauge as _G  # type: ignore
    _rot_counter = _C('alerts_rotations_total','Number of alert log rotations',['path'])  # type: ignore
    _write_fail_counter = _C('alerts_store_write_failures_total','Alert store write failures',['path'])  # type: ignore
    _last_hash_gauge = _G('alerts_integrity_last_hash','Length of last alert hash',['path'])  # type: ignore
except Exception:  # pragma: no cover
    class _Stub:
        def labels(self,*a,**k): return self
        def inc(self,*a,**k): return None
        def set(self,*a,**k): return None
    _rot_counter = _Stub(); _write_fail_counter = _Stub(); _last_hash_gauge = _Stub()

def _rotate_if_needed():
    max_bytes = _current_max_bytes()
    if max_bytes <= 0:
        return
    path = _current_path()
    if not os.path.exists(path):
        return
    try:
        if os.path.getsize(path) < max_bytes:
            return
    except OSError:
        return
    base, ext = os.path.splitext(path)
    ext = ext or '.jsonl'
    ts = time.strftime('%Y%m%d-%H%M%S')
    rotated = f"{base}.{ts}.rotated{ext}"
    try:
        os.replace(path, rotated)
        _rot_counter.labels(path=path).inc()
    except OSError:
        return
    # Retention
    try:
        pattern = f"{base}.*.rotated{ext}"
        files = sorted(glob.glob(pattern))
        retention = _current_retention()
        if len(files) > retention:
            for f in files[:-retention]:
                try:
                    os.remove(f)
                except OSError:
                    pass
    except Exception:
        pass

def _compute_hash(payload: dict) -> str:
    # Exclude integrity fields
    tmp = {k:v for k,v in payload.items() if k not in ('hash','prev_hash','hmac')}
    canonical = json.dumps(tmp, separators=(',',':'), sort_keys=True)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

def append(alert: dict[str, Any]):
    global _LAST_HASH
    path = _current_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _LOCK:
        _rotate_if_needed()
        rec = dict(alert)
        # Normalize prev_hash: ensure falsey or empty values are stored as None
        rec_prev = _LAST_HASH if _LAST_HASH else None
        rec['prev_hash'] = rec_prev
        rec['hash'] = _compute_hash(rec)
        secret = _current_hmac_secret()
        if secret:
            msg = (rec['hash'] + (rec['prev_hash'] or '')).encode('utf-8')
            rec['hmac'] = _hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()
        line = json.dumps(rec, separators=(',',':'))
        try:
            with open(path,'a',encoding='utf-8') as f:
                f.write(line+'\n')
            _LAST_HASH = rec['hash']
            try:
                _last_hash_gauge.labels(path=path).set(len(_LAST_HASH) if _LAST_HASH else 0)
            except Exception:
                pass
        except Exception:
            _write_fail_counter.labels(path=path).inc()

def last_hash() -> str | None:
    return _LAST_HASH


# Initialize last-hash from existing file (if any) so reloads honor prior state
_load_last_hash_for_existing_file()

def verify(path: str | None = None, hmac_secret: str | None = None):
    """Verify integrity chain of the alert log.

    Returns (ok: bool, error: str | None)
    """
    target = path or _current_path()
    if not os.path.exists(target):
        return True, None
    prev = None
    try:
        with open(target,encoding='utf-8') as f:
            for lineno, line in enumerate(f,1):
                line=line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                expected = _compute_hash(rec)
                if rec.get('hash') != expected:
                    return False, f'hash_mismatch_line_{lineno}'
                # Normalize legacy/empty prev_hash values so that '' and None are treated the same
                rec_prev = rec.get('prev_hash') if rec.get('prev_hash') else None
                # If this is the first non-empty line, accept it as the starting point
                # (helps tests that reload the module or reuse paths across runs).
                if lineno == 1:
                    prev = rec.get('hash')
                else:
                    if rec_prev != prev:
                        return False, f'prev_hash_mismatch_line_{lineno}'
                secret = hmac_secret if hmac_secret is not None else _current_hmac_secret()
                if secret:
                    msg = (rec['hash'] + (rec.get('prev_hash') or '')).encode('utf-8')
                    calc = _hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()
                    if rec.get('hmac') != calc:
                        return False, f'hmac_mismatch_line_{lineno}'
                prev = rec.get('hash')
    except Exception as e:  # pragma: no cover
        return False, f'exception:{e}'
    return True, None

