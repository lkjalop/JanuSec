"""Detect unsigned executable events and emit endpoint:unsigned_exec factor.

Designed to be called from endpoint ingestion where events include 'signed' and 'sha256'/'md5'.
Debounces emissions per unique hash for 1 hour by default.
"""
from __future__ import annotations
import time
from typing import Optional
from src.core.factors.emission_tracker import record_emission

_SEEN = {}  # hash -> ts
DEBOUNCE_SECONDS = int(__import__('os').environ.get('UNSIGNED_EXEC_DEBOUNCE_SECONDS','3600') or 3600)

def check_and_emit(hopgraph, node_id: str, *, signed: Optional[bool] = None, file_hash: Optional[str] = None, flagWeight: Optional[float] = None) -> bool:
    """If unsigned (signed False or None) and risk hints present, emit factor on node and record emission.

    Returns True if emitted.
    """
    try:
        if signed is True:
            return False
        # Heuristic: if file_hash present or flagWeight high or flagged suspicious
        risk_score = 0.0
        if flagWeight:
            try: risk_score += float(flagWeight)
            except Exception: pass
        if file_hash:
            now = time.time()
            last = _SEEN.get(file_hash)
            if last and (now - last) < DEBOUNCE_SECONDS:
                return False
            _SEEN[file_hash] = now
            # prefer emission tied to hash node if present
            target_node = node_id
        else:
            # No hash: require flagWeight threshold
            if risk_score < 2.0:
                return False
            target_node = node_id
        hopgraph.add_node_factor(target_node, 'endpoint:unsigned_exec')
        try:
            record_emission('endpoint:unsigned_exec', decision_id=None, node_ids=[target_node])
        except Exception:
            pass
        return True
    except Exception:
        return False

__all__ = ['check_and_emit']
