"""Persistence helpers for CrowdStrike connector.

Provides optional Redis-backed token metadata storage and detection dedupe.
If Redis is not available the module falls back to an in-memory store (demo).
"""
from __future__ import annotations
import os
import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

_USE_REDIS = False
_REDIS_CLIENT = None
try:
    import redis
    _REDIS_CLIENT = redis.Redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
    # quick ping
    _REDIS_CLIENT.ping()
    _USE_REDIS = True
except Exception:
    logger.debug('Redis not available for CS persistence; using in-memory fallback')

# In-memory fallback structures
_INMEM_TOKEN: Dict[str, Any] = {}
_INMEM_DETECTIONS: Dict[str, float] = {}

try:
    from prometheus_client import Counter, Histogram
    # low-cardinality tenant label; ensure operator controls tenant cardinality
    DETECTION_DEDUPE = Counter('cs_detection_dedupe_total', 'Total detection dedupe checks', ['tenant'])
    DETECTION_DB_UPSERTS = Counter('cs_detection_db_upserts_total', 'Total detection DB upsert attempts', ['tenant','success'])
    DETECTION_DB_UPSERTS_DURATION = Histogram('cs_detection_db_upsert_duration_seconds', 'Duration of DB upsert attempts', ['tenant'])
except Exception:
    DETECTION_DEDUPE = None
    DETECTION_DB_UPSERTS = None
    DETECTION_DB_UPSERTS_DURATION = None


def _get_allowed_tenant(raw: str | None) -> str:
    """Sanitize tenant to a low-cardinality value using METRICS_ALLOWED_TENANTS env.

    If METRICS_ALLOWED_TENANTS is set (comma-separated), only those tenants are allowed
    and all others will be mapped to 'other'. If not set, return raw or 'default'.
    """
    try:
        if not raw:
            return os.getenv('DEFAULT_TENANT', 'default')
        allowed = os.getenv('METRICS_ALLOWED_TENANTS', '')
        if not allowed:
            return raw
        allowed_set = {t.strip() for t in allowed.split(',') if t.strip()}
        return raw if raw in allowed_set else 'other'
    except Exception:
        return raw or os.getenv('DEFAULT_TENANT', 'default')


def save_token_metadata(token: str, expiry: float) -> None:
    key = 'cs:token'
    if _USE_REDIS:
        try:
            _REDIS_CLIENT.hset(key, mapping={'token': token, 'expiry': expiry})
        except Exception:
            logger.exception('Failed to save token to redis')
    else:
        _INMEM_TOKEN['token'] = token
        _INMEM_TOKEN['expiry'] = expiry


def get_token_metadata() -> Optional[Dict[str, Any]]:
    key = 'cs:token'
    if _USE_REDIS:
        try:
            data = _REDIS_CLIENT.hgetall(key)
            if not data:
                return None
            return {'token': data.get(b'token').decode() if data.get(b'token') else None, 'expiry': float(data.get(b'expiry') or 0)}
        except Exception:
            logger.exception('Failed to read token from redis')
            return None
    else:
        return _INMEM_TOKEN.copy() if _INMEM_TOKEN else None


def persist_detection(detection_id: str, payload: Dict[str, Any], ttl: int = 60 * 60 * 24, tenant: str | None = None) -> bool:
    """Persist detection id (dedupe) and optionally store a small summary.

    Returns True if this detection was newly persisted, False if it was already seen.
    """
    key = f'cs:det:{detection_id}'
    now = time.time()
    if _USE_REDIS:
        try:
            # Use SETNX semantics via set(..., nx=True)
            ok = _REDIS_CLIENT.set(key, int(now), ex=ttl, nx=True)
            if ok:
                # store a compact payload for debugging (hash key)
                try:
                    _REDIS_CLIENT.set(f'{key}:payload', str(payload)[:1024], ex=ttl)
                except Exception:
                    pass
            if DETECTION_DEDUPE:
                try:
                    DETECTION_DEDUPE.labels(tenant or 'default').inc()
                except Exception:
                    pass
            return bool(ok)
        except Exception:
            logger.exception('Failed to persist detection in redis')
            return False
    else:
        if DETECTION_DEDUPE:
            try:
                DETECTION_DEDUPE.labels(tenant or 'default').inc()
            except Exception:
                pass
        if detection_id in _INMEM_DETECTIONS:
            return False
        _INMEM_DETECTIONS[detection_id] = now
        return True


def persist_to_db_if_available(detection_id: str, summary: Dict[str, Any], retries: int = 3, backoff: float = 0.5) -> bool:
    """Persist a small detection summary into the decisions table if a DB adapter is available.

    Returns True on success.
    """
    try:
        from database_adapter import db_manager
    except Exception:
        return False
    attempt = 0
    while attempt < retries:
        try:
            # Minimal insertion mapping; adjust schema as needed
            rec = {
                'event_id': detection_id,
                'verdict': 'vendor:detection',
                'confidence': float(summary.get('confidence', 0.5) if summary.get('confidence') is not None else 0.5),
                'reasons': summary.get('observables') or [],
                'timestamp': summary.get('ts') or time.time(),
            }
            # db_manager.store_decision is hypothetical; prefer insert helper if available
            if hasattr(db_manager, 'store_decision'):
                db_manager.store_decision(rec)
            else:
                try:
                    # best-effort direct SQL path
                    adapter = getattr(db_manager, 'adapter', None)
                    if adapter and hasattr(adapter, 'connection'):
                        conn = adapter.connection
                        # Synchronous bypass for demo - not ideal in async contexts
                        cur = conn.cursor()
                        cur.execute('INSERT INTO decisions(event_id, verdict, confidence, reasons, timestamp) VALUES (?,?,?,?,?)', (rec['event_id'], rec['verdict'], rec['confidence'], str(rec['reasons']), rec['timestamp']))
                        conn.commit()
                except Exception:
                    # ignore DB insertion if not available
                    pass
            return True
        except Exception:
            attempt += 1
            time.sleep(backoff * attempt)
    return False


async def persist_to_db_async(detection_id: str, summary: Dict[str, Any], tenant: str | None = None) -> bool:
    """Async persistence route that uses the repository layer to upsert a minimal decision record.

    This function is intended to be scheduled via asyncio.create_task from background loops so it
    does not block network IO.
    """
    try:
        # The repository expects an object with attributes; create a lightweight struct
        from types import SimpleNamespace
        from src.repositories.decisions_repo import upsert_decision as _upsert
        # Build a minimal decision-like object compatible with upsert_decision
        decision = SimpleNamespace()
        decision.factors = summary.get('observables') or []
        decision.verdict = 'vendor:detection'
        decision.confidence = float(summary.get('confidence', 0.5) or 0.5)
        decision.processing_time_ms = 0.0
        decision.stage_timings = {}
        decision.custody_hash = None
        # Call the canonical async repo helper (with retry semantics inside)
        start = time.time()
        await _upsert(detection_id, decision, None)
        dur = max(0.0, time.time() - start)
        if DETECTION_DB_UPSERTS_DURATION:
            try:
                DETECTION_DB_UPSERTS_DURATION.labels(tenant or 'default').observe(dur)
            except Exception:
                pass
        if DETECTION_DB_UPSERTS:
            try: DETECTION_DB_UPSERTS.labels(tenant or 'default', 'true').inc()
            except Exception: pass
        return True
    except Exception:
        logger.exception('Failed async DB persist for detection %s', detection_id)
        if DETECTION_DB_UPSERTS:
            try: DETECTION_DB_UPSERTS.labels(tenant or 'default', 'false').inc()
            except Exception: pass
        return False
