from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from typing import Any, Dict, List
import sys
import time
from hunt.dsl import run_query  # type: ignore

router = APIRouter(prefix="/api/v1/hunt", tags=["hunt"])

# Simple in-memory ring buffer for recent queries (not persisted; demo only)
_HUNT_QUERY_LOG: List[Dict[str, Any]] = []
_HUNT_QUERY_LOG_MAX = 100


def _get_decision_cache() -> dict:
    mod = sys.modules.get('src.api.runtime_state')
    if mod is not None:
        cache = getattr(mod, 'DECISION_CACHE', None)
        if cache is not None:
            return cache
    try:
        from .runtime_state import DECISION_CACHE  # type: ignore
        return DECISION_CACHE
    except Exception:
        return {}


@router.post('/run')
async def hunt_run(request: Request) -> Dict[str, Any]:
    try:
        spec = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(spec, dict):
        raise HTTPException(status_code=400, detail='bad_json')
    DECISION_CACHE = _get_decision_cache()
    results = run_query(spec, decisions)
    entry = {
        'ts': time.time(),
        'spec': spec,
        'result_count': len(results)
    }
    try:
        _HUNT_QUERY_LOG.append(entry)
        if len(_HUNT_QUERY_LOG) > _HUNT_QUERY_LOG_MAX:
            # truncate oldest
            del _HUNT_QUERY_LOG[0: len(_HUNT_QUERY_LOG) - _HUNT_QUERY_LOG_MAX]
    except Exception:
        pass
    return {'count': len(results), 'results': results[:spec.get('limit', 100)], 'query': spec}

_IP_RE = None

def _extract_ips_from_text(text: str) -> set:
    global _IP_RE
    if _IP_RE is None:
        import re
        _IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    import re
    return set(_IP_RE.findall(text))


@router.post('/sweep')
async def hunt_sweep(request: Request) -> Dict[str, Any]:
    """IOC sweep: search DECISION_CACHE for decisions matching supplied IPs/domains."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    tenant_id = body.get('tenant_id', '')
    scope = body.get('scope', 'tenant')
    iocs = body.get('iocs') or {}
    ips = set(iocs.get('ips') or [])
    domains = set(iocs.get('domains') or [])

    # Extract IPs from natural-language query when no explicit iocs provided
    natural_query = body.get('query') or ''
    if natural_query and not ips and not domains:
        ips = _extract_ips_from_text(natural_query)

    DECISION_CACHE = _get_decision_cache()
    decisions = list(DECISION_CACHE.values()) if isinstance(DECISION_CACHE, dict) else []
    matches = []
    for d in decisions:
        if scope == 'tenant' and d.get('tenant_id') and d.get('tenant_id') != tenant_id:
            continue
        hit = (
            (ips and d.get('dst_ip') in ips)
            or (ips and d.get('src_ip') in ips)
            or (domains and d.get('domain') in domains)
        )
        if hit:
            matches.append(d)
    # Generate query strings for SIEM platforms
    ip_list = sorted(ips)
    domain_list = sorted(domains)
    kql_parts = []
    spl_parts = []
    if ip_list:
        kql_parts.append('(' + ' or '.join(f'DestinationIp == "{ip}"' for ip in ip_list) + ')')
        spl_parts.append('(' + ' OR '.join(f'dest_ip="{ip}"' for ip in ip_list) + ')')
    if domain_list:
        kql_parts.append('(' + ' or '.join(f'DnsQueryName == "{d}"' for d in domain_list) + ')')
        spl_parts.append('(' + ' OR '.join(f'query="{d}"' for d in domain_list) + ')')
    generated_queries = {
        'kql': ' or '.join(kql_parts) if kql_parts else '',
        'spl': ' OR '.join(spl_parts) if spl_parts else '',
    }
    return {'ok': True, 'count': len(matches), 'matches': matches, 'generated_queries': generated_queries}


@router.get('/queries/recent')
async def hunt_recent_queries(limit: int = 25) -> Dict[str, Any]:
    try:
        items = list(reversed(_HUNT_QUERY_LOG))[:max(1, min(limit, _HUNT_QUERY_LOG_MAX))]
    except Exception:
        items = []
    return {'queries': items, 'count': len(items)}

__all__ = ['router']