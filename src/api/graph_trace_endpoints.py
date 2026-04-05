from fastapi import APIRouter, HTTPException
from typing import Any

router = APIRouter(prefix='/api/v1/graph', tags=['graph'])


@router.get('/trace')
def graph_trace(event_id: str, depth: int = 3) -> dict[str, Any]:
    try:
        from graph.unified import UG  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail='graph_unavailable')

    # Candidate node inference order:
    # 1. If event looks like a node already (contains ':'), try it
    # 2. Check DECISION_CACHE for the event and derive nodes from factors
    # 3. Try common prefixes: event:<id>, host:<id>, ip:<id>, proc:<id>
    candidates = []
    if ':' in event_id:
        candidates.append(event_id)

    try:
        from .runtime_state import DECISION_CACHE  # type: ignore
        dec = DECISION_CACHE.get(event_id)
        if dec:
            # factors may contain host:/ip:/proc: tokens
            f = list(getattr(dec, 'factors', []) or []) if not isinstance(dec, dict) else dec.get('factors', [])
            if isinstance(f, (list, tuple)):
                for fac in f:
                    if isinstance(fac, str) and ':' in fac:
                        candidates.append(fac)
            # event may include host/ip fields
            try:
                host = dec.get('host') if isinstance(dec, dict) else getattr(dec, 'host', None)
                ip = dec.get('ip') if isinstance(dec, dict) else getattr(dec, 'ip', None)
                if host:
                    candidates.append(f'host:{host}')
                if ip:
                    candidates.append(f'ip:{ip}')
            except Exception:
                pass
    except Exception:
        pass

    # fallback candidates
    candidates.extend([f'event:{event_id}', f'host:{event_id}', f'ip:{event_id}', f'proc:{event_id}'])

    explain = {'paths': []}
    hops = {'nodes': [], 'edges': []}
    used_node = None
    for node in candidates:
        try:
            res = UG.explain_chain(node, max_depth=depth, top_k=5, beam_width=8)
            # if provider returns paths/chains, accept this node
            if res and (res.get('paths') or res.get('chains')):
                explain = res
                used_node = node
                break
        except Exception:
            continue

    # Fetch k_hops for the selected or first candidate
    node_for_hops = used_node or candidates[0]
    try:
        hops = UG.k_hops(node_for_hops, k=depth)
    except Exception:
        hops = {'nodes': [], 'edges': []}

    return {'event_id': event_id, 'node': used_node or node_for_hops, 'explain': explain, 'k_hops': hops}
