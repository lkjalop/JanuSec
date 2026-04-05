from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, Optional
import math

from src.repositories.factor_weights_repo import upsert_factor_weight, load_weights
from src.repositories.feedback_repo import aggregate_votes

SNAPSHOT_PATH = 'data/factor_weight_snapshots.jsonl'


async def generate_candidate_weights(window: str = '30 days', tenant_id: Optional[str] = None, max_delta: float = 0.05) -> Dict[str, float]:
    """
    Generate candidate factor weights from feedback aggregation.
    - Uses simple logistic-ish normalization of net votes into [0.01, 0.99]
    - Applies guardrail to ensure no weight changes exceed max_delta relative to current weights
    - Writes a snapshot to SNAPSHOT_PATH for audit
    Returns candidate weight dict.
    """
    # Aggregate votes from feedback_repo (net vote counts per factor)
    try:
        agg = await aggregate_votes(window, tenant_id, limit=1000)
    except Exception:
        # If DB unavailable in tests or disabled via env, treat as no feedback
        agg = []

    # Load current weights (graceful fallback to defaults if DB disabled)
    try:
        current = await load_weights(tenant_id)
    except Exception:
        current = {}

    candidates: Dict[str, float] = {}
    for r in agg:
        factor = r['factor']
        net = r.get('net', 0) or 0
        total = r.get('total', 1) or 1
        # simple score in [-1,1]
        score = net / total
        # map to [0.05,0.95] (avoid extremes)
        w = 0.5 + 0.45 * score
        w = max(0.01, min(0.99, w))
        candidates[factor] = w

    # Apply guardrails relative to current weights
    adjusted: Dict[str, float] = {}
    for f, cw in candidates.items():
        prev = current.get(f, 0.5)
        delta = cw - prev
        if abs(delta) > max_delta:
            cw = prev + (max_delta if delta > 0 else -max_delta)
        # clip
        cw = max(0.01, min(0.99, cw))
        adjusted[f] = cw

    # Save snapshot line
    try:
        with open(SNAPSHOT_PATH, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps({'ts': datetime.utcnow().isoformat(), 'tenant_id': tenant_id, 'window': window, 'candidates': adjusted}) + '\n')
    except Exception:
        pass

    return adjusted


async def promote_candidates_to_prod(candidates: Dict[str, float], tenant_id: Optional[str] = None):
    """
    Promote the candidate weights to production DB (upsert). Caller must ensure canary/AB testing has passed.
    """
    for f, w in candidates.items():
        await upsert_factor_weight(f, float(w), tenant_id)
