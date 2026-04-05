from __future__ import annotations

import time
from typing import Any, Dict
from fastapi import APIRouter, Query

try:
    from integrations.threat_intel_client import CLIENT as TI_CLIENT  # type: ignore
except Exception:  # pragma: no cover
    TI_CLIENT = None  # type: ignore

router = APIRouter(prefix="/api/v1/intel", tags=["intel"])

def _derive_status(raw: Dict[str, Any]) -> Dict[str, Any]:
    now = time.time()
    sync_interval = int(raw.get('sync_interval', 900)) if isinstance(raw, dict) else 900
    last_sync = raw.get('last_sync', {}) if isinstance(raw, dict) else {}
    freshness: Dict[str, float] = {}
    stale: Dict[str, bool] = {}
    for src, ts in last_sync.items():
        try:
            age = now - float(ts)
            freshness[src] = age
            stale[src] = age > (2 * sync_interval)
        except Exception:
            continue
    raw['freshness_seconds'] = freshness
    raw['stale'] = stale
    return raw

@router.get("/status", operation_id='intel_status')
async def intel_status() -> Dict[str, Any]:
    if not TI_CLIENT or not getattr(TI_CLIENT, 'enabled', False):
        return {"enabled": False, "message": "Threat intel disabled"}
    base = TI_CLIENT.status()
    base['sync_interval'] = getattr(TI_CLIENT, 'sync_interval', 900)
    # Expose failure streaks per feed for UI/ops visibility
    try:
        base['failure_streaks'] = dict(getattr(TI_CLIENT, '_failure_streak', {}))
    except Exception:
        base['failure_streaks'] = {}
    base['confidence_stats'] = {
        k: sum(1 for _v,_c in v.items()) for k,v in getattr(TI_CLIENT, '_confidence', {}).items()
    }
    # Compute per-source item counts by scanning origins
    try:
        source_counts: Dict[str, int] = {}
        origins = getattr(TI_CLIENT, '_origins', {}) or {}
        for _kind, omap in origins.items():
            for _val, src in (omap or {}).items():
                if not src:
                    continue
                source_counts[src] = source_counts.get(src, 0) + 1
        base['source_counts'] = source_counts
    except Exception:
        base['source_counts'] = {}
    return _derive_status(base)

@router.get("/lookup")
async def intel_lookup(type: str = Query(..., pattern="^(ip|domain|url|hash|ja3|certfp)$"), value: str = Query(..., min_length=3)) -> Dict[str, Any]:
    """Lookup an IoC across loaded threat intel sets and return confidence & origins.

    Returns:
      { found: bool, type, value, confidence, origin, expired: bool }
    """
    if not TI_CLIENT or not getattr(TI_CLIENT, 'enabled', False):
        return { 'enabled': False, 'found': False, 'type': type, 'value': value }
    v = value.strip().lower()
    store_map = {
        'ip': (TI_CLIENT.ip_set, TI_CLIENT.ip_ttl),
        'domain': (TI_CLIENT.domain_set, TI_CLIENT.domain_ttl),
        'url': (TI_CLIENT.url_set, TI_CLIENT.url_ttl),
        'hash': (TI_CLIENT.hash_set, TI_CLIENT.hash_ttl),
        'ja3': (TI_CLIENT.ja3_set, TI_CLIENT.ja3_ttl),
        'certfp': (TI_CLIENT.certfp_set, TI_CLIENT.certfp_ttl),
    }
    store, ttl_map = store_map[type]
    found = v in store
    expired = False
    if found:
        exp = ttl_map.get(v)
        if exp and exp != float('inf') and exp < time.time():
            expired = True
            found = False
    confidence = TI_CLIENT.ioc_confidence(type if type != 'certfp' else 'certfp', v) if found else None
    origin = TI_CLIENT.origin_for(v) if found else None
    return {
        'enabled': True,
        'found': found,
        'expired': expired,
        'type': type,
        'value': value,
        'confidence': confidence,
        'origin': origin
    }

@router.get('/techniques')
async def intel_techniques() -> Dict[str, Any]:
    if not TI_CLIENT or not getattr(TI_CLIENT, 'enabled', False):
        return {'enabled': False, 'mappings': {}}
    try:
        return {'enabled': True, 'mappings': getattr(TI_CLIENT, 'factor_techniques', {})}
    except Exception:
        return {'enabled': True, 'mappings': {}}


@router.get('/techniques/provenance')
async def get_technique_provenance():
    try:
        from integrations.threat_intel_client import CLIENT
        return {'provenance': CLIENT.technique_provenance()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'error:{exc}')


@router.post('/feeds/{feed}/toggle')
async def toggle_feed(feed: str, payload: dict):
    try:
        enabled = bool(payload.get('enabled', True))
        tenant = payload.get('tenant_id')
        from integrations.threat_intel_client import CLIENT
        CLIENT.set_feed_enabled(feed, enabled, tenant_id=tenant)
        return {'feed': feed, 'enabled': enabled, 'tenant': tenant}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'error:{exc}')


_DEGRADATION_FLAGS = {
    'intel_offline': False,
    'scoring_fallback': False,
    'queue_backlog': False,
}


@router.get('/status/degradation')
async def get_degradation_status():
    return {'flags': _DEGRADATION_FLAGS}


@router.post('/status/degradation')
async def set_degradation_flag(payload: dict):
    name = (payload.get('name') or '').strip()
    if name not in _DEGRADATION_FLAGS:
        raise HTTPException(status_code=400, detail='unknown_flag')
    _DEGRADATION_FLAGS[name] = bool(payload.get('value'))
    return {'name': name, 'value': _DEGRADATION_FLAGS[name]}

__all__ = ['router']
