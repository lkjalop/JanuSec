"""Factor Emission Tracker

Records (factor, decision_id?, node_ids?) emissions for coverage gating and CI replay.

Design:
 - In-memory ring buffer (default max 5000 entries; configurable via EMITTED_FACTORS_BUFFER_MAX)
 - Rolling JSONL file (data/emitted_factors.log) appended per unique (decision_id,factor)
 - Deduplication: if decision_id provided we only count first emission toward metrics.
 - Decision ID optional (None) for node attribution events without a decision context yet.
 - Metrics: emitted_factor_total Counter (labels: factor)

API endpoint (implemented separately) consumes get_emitted(since) to return recent entries.

Thread-safety: lightweight RLock around mutations.
"""
from __future__ import annotations
import time, json, os, threading
from typing import List, Dict, Optional, Iterable

_LOCK = threading.RLock()
_BUFFER: List[Dict[str, any]] = []
_DEDUP: set[tuple[str,str]] = set()  # (decision_id, factor)
_LOG_PATH = os.getenv('EMITTED_FACTORS_LOG_PATH','data/emitted_factors.log')
_MAX = int(os.getenv('EMITTED_FACTORS_BUFFER_MAX','5000') or 5000)

try:  # best-effort metrics wiring
    from core.metrics.registry import metric_counter  # type: ignore
    _EMIT_COUNTER = metric_counter('emitted_factor_total','Total unique factor emissions (dedup by decision)', labels=['factor'])
except Exception:  # pragma: no cover
    _EMIT_COUNTER = None  # type: ignore

def _ensure_dir():
    try:
        os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
    except Exception:
        pass

def record_emission(factor: str, *, decision_id: Optional[str] = None, node_ids: Optional[Iterable[str]] = None, ts: Optional[float] = None) -> None:
    """Record a factor emission.

    decision_id: optional decision/event id; if supplied duplicates are ignored for metrics & log.
    node_ids: optional iterable of associated node ids (snapshot for debugging).
    ts: override timestamp (defaults to current time).
    """
    if not isinstance(factor, str) or not factor:
        return
    ts = ts or time.time()
    # Dedup key only when decision_id present
    key = (decision_id or '', factor)
    first = False
    with _LOCK:
        if decision_id and key in _DEDUP:
            # still keep an in-memory note (tag duplicate) for debugging if desired
            entry = {'factor': factor, 'decision_id': decision_id, 'ts': ts, 'duplicate': True}
            if node_ids:
                entry['nodes'] = list(node_ids)[:10]
            _BUFFER.append(entry)
        else:
            if decision_id:
                _DEDUP.add(key)
            entry = {'factor': factor, 'decision_id': decision_id, 'ts': ts}
            if node_ids:
                entry['nodes'] = list(node_ids)[:10]
            _BUFFER.append(entry)
            first = True
        # Trim buffer
        if len(_BUFFER) > _MAX:
            # keep newest entries
            _BUFFER[:] = _BUFFER[-_MAX:]
        if first and _EMIT_COUNTER:
            try:
                _EMIT_COUNTER.labels(factor=factor).inc()
            except Exception:
                pass
        # Append to log only for first unique emission (to keep file size bounded)
        if first:
            try:
                _ensure_dir()
                with open(_LOG_PATH, 'a', encoding='utf-8') as fh:
                    fh.write(json.dumps(entry, separators=(',',':')) + '\n')
            except Exception:
                pass

def get_emitted(since: Optional[float] = None) -> List[Dict[str, any]]:
    with _LOCK:
        if since is None:
            return list(_BUFFER)
        return [e for e in _BUFFER if e.get('ts',0) >= since]

__all__ = ['record_emission','get_emitted']
