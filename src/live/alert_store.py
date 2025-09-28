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
import os, json, time, glob, threading, hashlib, hmac as _hmac
from typing import Dict, Any

_PATH = os.getenv('ALERTS_LOG_PATH','artifacts/alerts/alerts.jsonl')
_MAX_BYTES = int(os.getenv('ALERTS_MAX_BYTES','20000000'))
_RETENTION = int(os.getenv('ALERTS_RETENTION','5'))
_HMAC_SECRET = os.getenv('ALERTS_HMAC_SECRET')
_LOCK = threading.Lock()
_LAST_HASH = None  # updated after each append

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
    if _MAX_BYTES <= 0: return
    if not os.path.exists(_PATH): return
    try:
        if os.path.getsize(_PATH) < _MAX_BYTES:
            return
    except OSError:
        return
    base, ext = os.path.splitext(_PATH)
    ext = ext or '.jsonl'
    ts = time.strftime('%Y%m%d-%H%M%S')
    rotated = f"{base}.{ts}.rotated{ext}"
    try:
        os.replace(_PATH, rotated)
        _rot_counter.labels(path=_PATH).inc()
    except OSError:
        return
    # Retention
    try:
        pattern = f"{base}.*.rotated{ext}"
        files = sorted(glob.glob(pattern))
        if len(files) > _RETENTION:
            for f in files[:-_RETENTION]:
                try: os.remove(f)
                except OSError: pass
    except Exception:
        pass

def _compute_hash(payload: dict) -> str:
    # Exclude integrity fields
    tmp = {k:v for k,v in payload.items() if k not in ('hash','prev_hash','hmac')}
    canonical = json.dumps(tmp, separators=(',',':'), sort_keys=True)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

def append(alert: Dict[str, Any]):
    global _LAST_HASH
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    with _LOCK:
        _rotate_if_needed()
        rec = dict(alert)
        rec['prev_hash'] = _LAST_HASH
        rec['hash'] = _compute_hash(rec)
        if _HMAC_SECRET:
            msg = (rec['hash'] + (rec['prev_hash'] or '')).encode('utf-8')
            rec['hmac'] = _hmac.new(_HMAC_SECRET.encode('utf-8'), msg, hashlib.sha256).hexdigest()
        line = json.dumps(rec, separators=(',',':'))
        try:
            with open(_PATH,'a',encoding='utf-8') as f:
                f.write(line+'\n')
            _LAST_HASH = rec['hash']
            try:
                _last_hash_gauge.labels(path=_PATH).set(len(_LAST_HASH) if _LAST_HASH else 0)
            except Exception:
                pass
        except Exception:
            _write_fail_counter.labels(path=_PATH).inc()

def last_hash() -> str | None:
    return _LAST_HASH

def verify(path: str | None = None, hmac_secret: str | None = None):
    """Verify integrity chain of the alert log.

    Returns (ok: bool, error: str | None)
    """
    target = path or _PATH
    if not os.path.exists(target):
        return True, None
    prev = None
    try:
        with open(target,'r',encoding='utf-8') as f:
            for lineno, line in enumerate(f,1):
                line=line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                expected = _compute_hash(rec)
                if rec.get('hash') != expected:
                    return False, f'hash_mismatch_line_{lineno}'
                if rec.get('prev_hash') != prev:
                    return False, f'prev_hash_mismatch_line_{lineno}'
                secret = hmac_secret if hmac_secret is not None else _HMAC_SECRET
                if secret:
                    msg = (rec['hash'] + (rec.get('prev_hash') or '')).encode('utf-8')
                    calc = _hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()
                    if rec.get('hmac') != calc:
                        return False, f'hmac_mismatch_line_{lineno}'
                prev = rec.get('hash')
    except Exception as e:  # pragma: no cover
        return False, f'exception:{e}'
    return True, None

