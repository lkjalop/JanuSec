"""Alert query endpoints (recent/search) with shared ring state."""
from __future__ import annotations
import os, json, hashlib, threading
from threading import Lock
from fastapi import APIRouter, Depends, HTTPException
from .auth_rate_limit import alerts_auth
from .dependencies import get_platform_state
from .state import PlatformState
try:
    from api.server import track_alert_event  # type: ignore
except Exception:
    def track_alert_event(*a, **k):
        return None

ALERT_RING: list[dict] = []
ALERT_RING_LOCK = Lock()
ALERT_RING_MAX = int(os.getenv('ALERT_RING_MAX','500'))
ALERTS_LOG_PATH = os.getenv('ALERTS_LOG_PATH','artifacts/alerts/alerts.jsonl')  # legacy single-tenant path (still used if no tenant_id)


def _base_alert_log_path() -> str:
    return os.getenv('ALERTS_LOG_PATH', ALERTS_LOG_PATH)


def get_tenant_alert_path(tenant_id: str | None) -> str:
    """Return path for tenant alert chain file (partition) or legacy file if tenant_id is None."""
    base_path = _base_alert_log_path()
    if tenant_id:
        base_dir = os.path.dirname(base_path) or '.'
        return os.path.join(base_dir, tenant_id, 'alerts.jsonl')
    return base_path
PERSIST_BACKEND = os.getenv('PERSIST_BACKEND','jsonl').lower()  # jsonl|postgres|dual
INCLUDE_PERSIST = os.getenv('ALERTS_PERSIST_HISTORY', '1') not in ('0', 'false', 'no')
_ALERT_CHAIN_LOCK = threading.Lock()
_LAST_HASH = None  # in-memory tail for integrity chain

router = APIRouter()

@router.get('/api/v1/alerts/recent')
async def alerts_recent(limit: int = 50, tenant_id: str | None = None, ident: str = Depends(alerts_auth), state: PlatformState = Depends(get_platform_state)):
    limit = max(0, min(limit, 200))
    snapshots = state.recent_alerts(limit=limit, tenant_id=tenant_id)
    data = [snap.model_dump() for snap in snapshots]
    return {'alerts': data, 'count': len(data), 'tenant_filtered': bool(tenant_id)}


@router.get('/api/v1/alerts/search')
async def alerts_search(host: str | None = None, verdict: str | None = None, min_score: float | None = None, since_ts: float | None = None, until_ts: float | None = None, limit: int = 100, offset: int = 0, tenant_id: str | None = None, ident: str = Depends(alerts_auth), state: PlatformState = Depends(get_platform_state)):
    def include(rec: dict) -> bool:
        if tenant_id and rec.get('tenant_id') != tenant_id:
            return False
        if host and rec.get('host') != host:
            return False
        if verdict and rec.get('verdict') != verdict:
            return False
        score = rec.get('score', 0)
        if min_score is not None and score < min_score:
            return False
        ts_val = rec.get('ts') or rec.get('timestamp') or 0
        if since_ts and ts_val < since_ts:
            return False
        if until_ts and ts_val > until_ts:
            return False
        return True

    rows: list[dict] = []

    # In-memory recent alerts
    snapshots = state.recent_alerts(limit=limit + offset + 100, tenant_id=tenant_id)
    for snap in snapshots:
        rec = snap.model_dump()
        if include(rec):
            rows.append(rec)

    # Alert ring for freshest entries not yet persisted
    with ALERT_RING_LOCK:
        for rec in ALERT_RING:
            if include(rec):
                rows.append(rec.copy())

    # Optional persisted history
    if INCLUDE_PERSIST:
        paths: list[str] = []
        base_path = _base_alert_log_path()
        base_dir = os.path.dirname(base_path) or '.'
        if tenant_id:
            paths.append(get_tenant_alert_path(tenant_id))
        else:
            try:
                if os.path.isdir(base_dir):
                    for entry in os.listdir(base_dir):
                        t_path = os.path.join(base_dir, entry, 'alerts.jsonl')
                        if os.path.isfile(t_path):
                            paths.append(t_path)
            except Exception:
                pass
            paths.append(base_path)
        for path in paths:
            try:
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as handle:
                        for line in handle:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                rec = json.loads(line)
                            except Exception:
                                continue
                            if include(rec):
                                rows.append(rec)
            except FileNotFoundError:
                continue

    rows.sort(key=lambda r: r.get('ts') or r.get('timestamp') or 0, reverse=True)
    deduped: list[dict] = []
    seen: set = set()
    for rec in rows:
        key = rec.get('id') or (rec.get('ts'), rec.get('timestamp'))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rec)
    rows = deduped
    slice_rows = rows[offset: offset + limit]
    return {
        'total': len(rows),
        'returned': len(slice_rows),
        'offset': offset,
        'limit': limit,
        'alerts': slice_rows,
        'tenant_filtered': bool(tenant_id),
    }


def _jsonl_path_for(alert: dict) -> str:
    return get_tenant_alert_path(alert.get('tenant_id'))

# Maintain per-tenant last hash (in-memory)
_TENANT_LAST_HASH: dict[str, str | None] = {}

def _persist_jsonl(alert: dict):
    try:
        path = _jsonl_path_for(alert)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tenant_id = alert.get('tenant_id') or '_legacy'
        with _ALERT_CHAIN_LOCK:
            prev = _TENANT_LAST_HASH.get(tenant_id)
            body = {k:v for k,v in alert.items() if k not in ('hash','prev_hash')}
            body['prev_hash'] = prev
            payload = json.dumps(body, sort_keys=True, separators=(',',':')).encode()
            h = hashlib.sha256(payload).hexdigest()
            body['hash'] = h
            with open(path,'a',encoding='utf-8') as f:
                f.write(json.dumps(body)+'\n')
            _TENANT_LAST_HASH[tenant_id] = h
    except Exception:
        pass

def _persist_postgres(alert: dict):  # stub implementation (extend later)
    try:
        # Lazy import placeholder – real implementation would enqueue batch insert
        if os.getenv('POSTGRES_DSN'):
            # For now just note intention in log file for visibility
            marker = _base_alert_log_path() + '.pg_intent'
            with open(marker,'a',encoding='utf-8') as f:
                f.write(json.dumps({'id': alert.get('id'), 'ts': alert.get('ts'), 'verdict': alert.get('verdict')})+'\n')
    except Exception:
        pass

def append_alert(alert: dict):
    """Append alert with ring buffering + pluggable persistence backend."""
    with ALERT_RING_LOCK:
        ALERT_RING.append(alert)
        if len(ALERT_RING) > ALERT_RING_MAX:
            del ALERT_RING[0: len(ALERT_RING) - ALERT_RING_MAX]
    try:
        track_alert_event(alert.get('ts') or alert.get('timestamp'))
    except Exception:
        pass
    backend = PERSIST_BACKEND
    if INCLUDE_PERSIST and backend in ('jsonl','dual'):
        _persist_jsonl(alert)
    if backend in ('postgres','dual'):
        _persist_postgres(alert)

__all__ = ['router','append_alert','ALERT_RING','ALERT_RING_MAX','get_tenant_alert_path']




