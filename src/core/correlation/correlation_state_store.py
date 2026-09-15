"""Simple TTL JSON persistence for correlation state (temporal buffers & cooccurrence pairs).

Environment overrides:
  CORRELATION_STATE_PATH (default data/correlation_state.json)
  CORRELATION_STATE_TTL_SECONDS (default 86400)
  CORRELATION_STATE_FLUSH_INTERVAL (default 30) -> min seconds between flushes

Best-effort: failures are swallowed. Flushes rate-limited to avoid IO amplification.
"""
from __future__ import annotations
import json, os, time
from pathlib import Path
from typing import Dict, Any, Tuple

STATE_PATH = os.getenv('CORRELATION_STATE_PATH','data/correlation_state.json')
TTL_SECONDS = float(os.getenv('CORRELATION_STATE_TTL_SECONDS','86400') or 86400)
FLUSH_INTERVAL = float(os.getenv('CORRELATION_STATE_FLUSH_INTERVAL','30') or 30)

_last_flush = 0.0

def _now() -> float:
    return time.time()

def load_state() -> Dict[str, Any]:
    try:
        p = Path(STATE_PATH)
        if not p.exists():
            return {'pairs': {}, 'temporal': {}}
        raw = json.loads(p.read_text(encoding='utf-8'))
        return {'pairs': dict(raw.get('pairs') or {}), 'temporal': dict(raw.get('temporal') or {})}
    except Exception:
        return {'pairs': {}, 'temporal': {}}

def prune_state(state: Dict[str, Any]) -> None:
    cutoff = _now() - TTL_SECONDS
    # pairs: {"factorA|factorB": {"cnt": int, "ts": float}}
    try:
        for k, meta in list(state.get('pairs', {}).items()):
            ts = float(meta.get('ts') or 0)
            if ts < cutoff:
                state['pairs'].pop(k, None)
    except Exception:
        pass
    # temporal: {entity: [(ts,factor), ...]}
    try:
        for ent, buf in list(state.get('temporal', {}).items()):
            new_buf = [e for e in buf if (isinstance(e,(list,tuple)) and len(e)==2 and float(e[0]) >= cutoff)]
            if new_buf:
                state['temporal'][ent] = new_buf
            else:
                state['temporal'].pop(ent, None)
    except Exception:
        pass

def flush_state(pairs: Dict[Tuple[str,str], Tuple[int,float]], temporal_buffers: Dict[str, list[tuple[float,str]]]) -> None:
    global _last_flush
    now = _now()
    if (now - _last_flush) < FLUSH_INTERVAL:
        return
    _last_flush = now
    try:
        state = load_state()
        prune_state(state)
        # merge cooccurrence pairs
        for (a,b), (cnt, ts) in pairs.items():
            key = f"{a}|{b}"
            prev = state['pairs'].get(key)
            if prev:
                # update count & timestamp if newer
                try:
                    prev_cnt = int(prev.get('cnt') or 0)
                except Exception:
                    prev_cnt = 0
                if cnt > prev_cnt:
                    state['pairs'][key] = {'cnt': cnt, 'ts': ts}
            else:
                state['pairs'][key] = {'cnt': cnt, 'ts': ts}
        # merge temporal buffers (no dedup beyond max buffer trimming handled upstream)
        for ent, buf in temporal_buffers.items():
            recs = state['temporal'].setdefault(ent, [])
            # append keeping simple size cap
            for (ts, fac) in buf[-256:]:
                recs.append([ts, fac])
            # trim
            if len(recs) > 256:
                del recs[:len(recs)-256]
        # write file atomically-ish
        Path(STATE_PATH).parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(STATE_PATH + '.tmp')
        tmp.write_text(json.dumps(state, separators=(',',':')), encoding='utf-8')
        tmp.replace(Path(STATE_PATH))
        from .metrics_correlation import inc_state_persist  # type: ignore
        inc_state_persist('flush')
    except Exception:
        try:
            from .metrics_correlation import inc_state_persist  # type: ignore
            inc_state_persist('error')
        except Exception:
            pass

__all__ = ['load_state','flush_state','prune_state']
