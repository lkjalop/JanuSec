"""Drift Analyzer for factor frequency distributions.

Computes Jensen-Shannon divergence between two discrete factor distributions.
Strategy:
  - Periodically fetch recent decisions for two adjacent windows (e.g., last 30m and the 30m before that).
  - Extract factors (flatten list) and count occurrences.
  - Normalize to probability distributions.
  - Compute JS divergence = 0.5 * KL(P||M) + 0.5 * KL(Q||M) where M = 0.5(P+Q).
  - Record gauge via metrics collector (factor_freq_js_divergence).

If insufficient data (< MIN_EVENTS threshold) sets gauge to 0.
"""
from __future__ import annotations
import math, time, asyncio, logging
from typing import Dict, List
from db.database import get_pool

logger = logging.getLogger(__name__)

WINDOW_MINUTES = 30
MIN_EVENTS = 20

async def _factor_counts(conn, start_ts, end_ts) -> Dict[str,int]:
    rows = await conn.fetch(
        """
        SELECT factors FROM decisions
        WHERE created_at >= to_timestamp($1) AND created_at < to_timestamp($2)
        """, start_ts, end_ts
    )
    counts: Dict[str,int] = {}
    for r in rows:
        farr = r.get('factors')
        if isinstance(farr, list):
            for f in farr:
                if isinstance(f, str):
                    counts[f] = counts.get(f,0)+1
    return counts

def _normalize(counts: Dict[str,int]) -> Dict[str,float]:
    total = sum(counts.values())
    if total == 0:
        return {}
    return {k: v/total for k,v in counts.items()}

def _js_divergence(p: Dict[str,float], q: Dict[str,float]) -> float:
    if not p or not q:
        return 0.0
    keys = set(p.keys()) | set(q.keys())
    m = {k: 0.5*(p.get(k,0.0)+q.get(k,0.0)) for k in keys}
    def kl(a,b):
        s = 0.0
        for k in keys:
            av = a.get(k,0.0)
            bv = b.get(k,0.0)
            if av > 0 and bv > 0:
                s += av * math.log(av/bv)
        return s
    return 0.5*kl(p,m)+0.5*kl(q,m)

async def compute_js_divergence(metrics):
    try:
        pool = await get_pool()
    except Exception:
        return
    end = time.time()
    start_current = end - WINDOW_MINUTES*60
    start_prev = start_current - WINDOW_MINUTES*60
    try:
        async with pool.acquire() as conn:
            prev_counts = await _factor_counts(conn, start_prev, start_current)
            curr_counts = await _factor_counts(conn, start_current, end)
            if sum(prev_counts.values()) < MIN_EVENTS or sum(curr_counts.values()) < MIN_EVENTS:
                await metrics.record_embedding_stats(metrics.gauges.get('embedding_avg_norm',0.0))
                metrics.gauges['factor_freq_js_divergence'] = 0.0
                return
            p = _normalize(prev_counts)
            q = _normalize(curr_counts)
            js = _js_divergence(p,q)
            metrics.gauges['factor_freq_js_divergence'] = js
    except Exception as e:
        logger.debug(f"Drift computation skipped: {e}")

async def drift_loop(metrics, stop_event: asyncio.Event):
    while not stop_event.is_set():
        await compute_js_divergence(metrics)
        await asyncio.sleep(WINDOW_MINUTES*60)
