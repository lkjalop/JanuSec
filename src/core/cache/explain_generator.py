from __future__ import annotations

import asyncio
import time
from typing import Dict, Any


async def compute_explain(fingerprint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Compute an explanation for the given fingerprint + payload.

    Strategy:
    - Prefer the unified graph explain chain when available (`graph.unified.UG`).
    - Try reasonable node ids: `host:<host>`, `session:<fingerprint>`, `incident:<fingerprint>`.
    - If no graph provider is available, synthesize a lightweight explain using
      available `payload['factors']` and the `src.explain.dread.aggregate` helper.
    """
    await asyncio.sleep(0)  # yield to event loop
    start = time.time()
    # Try unified graph explain
    try:
        from src.graph.unified import UG
        # Candidate node ids
        candidates = []
        host = None
        try:
            host = payload.get('host') or payload.get('hostname') or payload.get('host_name')
        except Exception:
            host = None
        if host:
            candidates.append(f'host:{host}')
        candidates.append(f'session:{fingerprint}')
        candidates.append(f'incident:{fingerprint}')
        for node in candidates:
            try:
                explanation = UG.explain_chain(node, max_depth=4, top_k=3, beam_width=5)
                # If explanation looks meaningful (has chains or subgraph), return it
                if isinstance(explanation, dict) and (explanation.get('chains') or explanation.get('subgraph')):
                    explanation.setdefault('meta', {})
                    explanation['meta'].update({'source': 'unified_hopgraph', 'node': node, 'generated_at': start})
                    return explanation
            except Exception:
                continue
    except Exception:
        # Graph provider not available or error occurred; fall back
        pass

    # Fallback synthesized explain
    try:
        from src.explain.dread import aggregate as _dread_aggregate
    except Exception:
        _dread_aggregate = None

    factors = payload.get('factors') or []
    dread_summary = _dread_aggregate({'cves': payload.get('cves')}) if _dread_aggregate else {}
    out = {
        'fingerprint': fingerprint,
        'generated_at': start,
        'factors': factors,
        'n_factors': len(factors) if isinstance(factors, list) else 0,
        'dread': dread_summary,
        'meta': {'source': 'synth_fallback', 'generated_at': start}
    }
    return out


__all__ = ['compute_explain']
