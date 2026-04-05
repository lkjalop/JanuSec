from __future__ import annotations

from fastapi import APIRouter, HTTPException
from typing import Dict, Any

try:
    from incident.persistence import load_incident  # type: ignore
except Exception:
    from src.incident.persistence import load_incident  # type: ignore

from src.core.cache.explanation_cache import ExplanationCache

router = APIRouter(prefix='/api/v1/explain', tags=['Explainability'])

# initialize cache
_EXPLAIN_CACHE = ExplanationCache()


@router.get('/incident/{fp}')
async def explain_incident(fp: str) -> Dict[str, Any]:
    """Return explanation for an incident, using ExplanationCache as a fast path.

    Cache keying: 'incident:{fp}'. TTL can be overridden via EXPLAIN_CACHE_TTL env var.
    """
    key = f"incident:{fp}"
    # try cache
    cached = _EXPLAIN_CACHE.get(key)
    if cached:
        return {'fingerprint': fp, 'payload': cached.get('payload'), 'explain': cached.get('payload', {}).get('factors', {}), 'cache': 'hit', 'meta': cached.get('meta', {})}

    inc = load_incident(fp)
    if inc is None:
        raise HTTPException(status_code=404, detail='not_found')
    # assume stored payload has 'factors' and 'contributions'
    payload = inc.get('payload', {})

    # store in cache for future fast retrieval
    try:
        ttl = int(os.getenv('EXPLAIN_CACHE_TTL', '3600')) if os.getenv('EXPLAIN_CACHE_TTL') else 3600
    except Exception:
        ttl = 3600
    try:
        _EXPLAIN_CACHE.set(key, payload, ttl=ttl, meta={'source': 'incident_store'})
    except Exception:
        pass

    return {'fingerprint': fp, 'payload': payload, 'explain': payload.get('factors', {}), 'cache': 'miss'}


# ATT&CK inference stub
@router.post('/attack/infer')
async def infer_attack(payload: Dict[str, Any]) -> Dict[str, Any]:
    # payload: {'factors': {...}, 'sequence': [...]}
    f = payload.get('factors', {})
    seq = payload.get('sequence', [])
    tactics = []
    if f.get('prompt_injection_probability', 0) > 0.5:
        tactics.append('ATLAS:InitialAccess')
    if f.get('signature_match'):
        tactics.append('ATLAS:Execution')
    return {'tactics': tactics, 'confidence': 0.6}
