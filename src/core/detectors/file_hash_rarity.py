"""Detector for file hash rarity using runtime.file_hash_factors or file_hash history."""
from __future__ import annotations

from typing import Any, Dict, List
import time, math, json, os
from collections import deque
def file_hash_rarity_factors(runtime: Any, files: List[Dict[str, Any]] | None = None, rarity_threshold: float = 0.4) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    history = getattr(runtime, 'file_hash_factors', None) or {}

    # Build counts from history (deque lengths)
    # Exponential decay weighting: effective count = sum(exp(-(age / tau)))
    tau = 0.0
    try:
        tau = float(os.getenv('FILE_HASH_DECAY_SECONDS', '0') or 0.0)
    except Exception:
        tau = 0.0
    now = time.time()
    counts: Dict[str, float] = {}
    total = 0.0
    for h, dq in history.items():
        eff = 0.0
        if tau and tau > 0:
            for ts in list(dq):
                try:
                    age = max(0.0, now - float(ts))
                    eff += math.exp(-age / tau)
                except Exception:
                    continue
        else:
            try:
                eff = float(len(dq)) if hasattr(dq,'__len__') else float(dq or 0)
            except Exception:
                eff = 0.0
        counts[h] = eff
        total += eff

    # If no history, fallback: if files provided, treat singletons as rare
    candidates: List[Dict[str, Any]] = []
    for f in (files or []):
        if not isinstance(f, dict):
            continue
        sha = f.get('sha256')
        if not sha:
            continue
        c = float(counts.get(sha, 0.0))
        rarity = 1.0
        if total > 0:
            rarity = 1.0 - min(1.0, (c / float(max(1.0, total))))
        # Score proportional to rarity but clamp
        score = min(0.95, max(0.0, 0.2 + (rarity * 0.8)))
        if rarity >= rarity_threshold:
            candidates.append({'sha256': sha, 'count_effective': round(c,3), 'rarity': round(rarity, 3), 'factor': 'file_hash_rarity', 'score': round(score, 3), 'reason': f'hash {sha} rare (effective={c:.2f})'})
    return candidates


def update_runtime_hash_history(runtime: Any, files: List[Dict[str, Any]] | None = None) -> None:
    """Update runtime.file_hash_factors with timestamped observations.

    Each hash maps to a bounded deque of timestamps (most recent). This keeps a
    temporal window for rarity scoring and bounds memory use.
    """
    if runtime is None or not files:
        return
    try:
        hist = getattr(runtime, 'file_hash_factors', None)
        if hist is None:
            try:
                runtime.file_hash_factors = {}
                hist = runtime.file_hash_factors
            except Exception:
                return
        for f in (files or []):
            if not isinstance(f, dict):
                continue
            sha = f.get('sha256')
            if not sha:
                continue
            try:
                ts = time.time()
                dq = hist.get(sha)
                if dq is None:
                    maxlen = int(os.getenv('FILE_HASH_HISTORY_MAXLEN', '200') or 200)
                    hist[sha] = deque([ts], maxlen=maxlen)
                else:
                    try:
                        dq.append(ts)
                    except Exception:
                        maxlen = int(os.getenv('FILE_HASH_HISTORY_MAXLEN', '200') or 200)
                        hist[sha] = deque([ts], maxlen=maxlen)
                # Enforce distinct hash key cap immediately after insertion
                try:
                    max_keys = int(os.getenv('FILE_HASH_HISTORY_MAX_KEYS','5000') or 5000)
                    if isinstance(hist, dict) and len(hist) > max_keys:
                        excess = len(hist) - max_keys
                        ordered = sorted(hist.items(), key=lambda kv: len(kv[1]) if hasattr(kv[1],'__len__') else 0)
                        for k,_dq in ordered[:excess]:
                            try: hist.pop(k, None)
                            except Exception: pass
                except Exception:
                    pass
            except Exception:
                continue
    except Exception:
        pass
