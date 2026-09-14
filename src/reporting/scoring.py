"""Scoring helpers for report forwarding and backlog prioritization."""
from __future__ import annotations
import os
import math
from typing import Dict, Any

# Default scoring weights (can be overridden via SCORING_WEIGHTS_JSON env var)
DEFAULT_WEIGHTS = {
    'w_triage': 0.5,
    'w_confidence': 0.2,
    'w_evidence_count': 0.15,
    'w_novelty': 0.1,
    'w_time_decay': 0.05,
}


def _load_weights() -> Dict[str, float]:
    import json
    raw = os.getenv('SCORING_WEIGHTS_JSON')
    if not raw:
        return DEFAULT_WEIGHTS.copy()
    try:
        js = json.loads(raw)
        out = DEFAULT_WEIGHTS.copy()
        for k, v in js.items():
            if k in out:
                out[k] = float(v)
        return out
    except Exception:
        return DEFAULT_WEIGHTS.copy()


def time_decay_score(age_seconds: float, half_life_hours: float = 24.0) -> float:
    """Simple exponential decay for older events; returns value in [0,1]."""
    try:
        hl = float(half_life_hours) * 3600.0
        if hl <= 0:
            return 1.0
        return math.exp(-math.log(2) * (age_seconds / hl))
    except Exception:
        return 1.0


def compute_score(row: Dict[str, Any], now_ts: float = None) -> float:
    """Compute composite score for a row using configured weights.

    Expected row keys: 'triage_score' (0..1), 'confidence' (0..1), 'evidence_count' (int),
    'novelty' (0..1), 'ingested_ts' (epoch seconds)
    """
    if now_ts is None:
        import time
        now_ts = time.time()
    w = _load_weights()
    tri = float(row.get('triage_score') or 0.0)
    conf = float(row.get('confidence') or 0.0)
    evidence_count = float(row.get('evidence_count') or row.get('evidence_len') or 0.0)
    # normalize evidence count using log scale
    evidence_norm = min(1.0, math.log1p(evidence_count) / math.log1p(10)) if evidence_count > 0 else 0.0
    novelty = float(row.get('novelty') or 0.0)
    ingested = float(row.get('ingested_ts') or row.get('created_ts') or now_ts)
    age = max(0.0, now_ts - ingested)
    td = time_decay_score(age)
    score = (
        w['w_triage'] * tri
        + w['w_confidence'] * conf
        + w['w_evidence_count'] * evidence_norm
        + w['w_novelty'] * novelty
        + w['w_time_decay'] * td
    )
    return float(score)
