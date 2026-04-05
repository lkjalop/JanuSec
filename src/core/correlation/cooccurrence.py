from __future__ import annotations
import time, os
from typing import Dict, Tuple
try:  # metrics optional
    from .metrics_correlation import inc_cooccurrence_pairs  # type: ignore
except Exception:  # pragma: no cover
    def inc_cooccurrence_pairs(*_a, **_k):
        return None
try:  # persistence flush optional
    from .correlation_state_store import flush_state  # type: ignore
except Exception:  # pragma: no cover
    def flush_state(*_a, **_k):
        return None

_MAX_PAIRS = int(os.getenv("COOCCURRENCE_MAX_PAIRS", "5000"))
_DECAY_SECONDS = float(os.getenv("COOCCURRENCE_DECAY_SECONDS", "86400"))

class CoOccurrenceTracker:
    def __init__(self):
        self.pairs: Dict[Tuple[str,str], Tuple[int, float]] = {}

    def _key(self, a: str, b: str) -> Tuple[str,str]:
        if a <= b:
            return (a,b)
        return (b,a)

    def record(self, factors: list[str]):
        now = time.time()
        # naive O(n^2) small n
        new_pairs = 0
        for i in range(len(factors)):
            for j in range(i+1, len(factors)):
                k = self._key(factors[i], factors[j])
                cnt, ts = self.pairs.get(k, (0, now))
                self.pairs[k] = (cnt+1, now)
                new_pairs += 1
        # prune if too large
        if len(self.pairs) > _MAX_PAIRS:
            # drop oldest 10%
            items = sorted(self.pairs.items(), key=lambda x: x[1][1])
            drop = int(len(items) * 0.1)
            for k,_v in items[:drop]:
                self.pairs.pop(k, None)
        # decay stale entries
        cutoff = now - _DECAY_SECONDS
        for k,(cnt, ts) in list(self.pairs.items()):
            if ts < cutoff:
                self.pairs.pop(k, None)
        if new_pairs:
            inc_cooccurrence_pairs(new_pairs)
        # flush state best-effort (temporal buffers merged in sequencer)
        try:
            from .temporal_sequencer import GLOBAL_TEMPORAL_SEQUENCER  # type: ignore
            flush_state(self.pairs, getattr(GLOBAL_TEMPORAL_SEQUENCER, 'buffers', {}))
        except Exception:
            pass

    def score_pair(self, a: str, b: str) -> float:
        # Simple PMI-ish proxy: log(count+1)
        import math
        k = self._key(a,b)
        cnt, _ts = self.pairs.get(k, (0,0))
        return round(math.log(cnt+1, 2), 4)

GLOBAL_COOCCURRENCE = CoOccurrenceTracker()

__all__ = ["CoOccurrenceTracker", "GLOBAL_COOCCURRENCE"]
