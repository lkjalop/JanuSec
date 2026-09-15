from __future__ import annotations
"""Minimal temporal sequencer implementation (feature-flagged).

Tracks recent factors per entity (host, user, process, ip) in a rolling window
and exposes simple pattern matching for multi-stage sequences. This is a
lightweight baseline; intended to be extended with scoring & adaptive decay.
"""
import time
from collections import deque, defaultdict
from typing import Dict, Deque, Tuple, List

DEFAULT_WINDOW_SECONDS = 900  # 15 minutes baseline
MAX_EVENTS_PER_ENTITY = 200

# Example pattern templates (ordered list of substrings to match in factor names)
DEFAULT_PATTERNS = [
    ('initial_access_chain', ['identity:', 'endpoint:', 'net:']),
    ('privilege_lateral_exfil', ['privilege', 'lateral', 'exfil']),
]

class TemporalSequencer:
    def __init__(self, window_seconds: int = DEFAULT_WINDOW_SECONDS):
        self.window = window_seconds
        self.events: Dict[str, Deque[Tuple[float, str]]] = defaultdict(lambda: deque())
        self.patterns = list(DEFAULT_PATTERNS)

    def update(self, entity: str, factor: str, ts: float | None = None) -> None:
        ts = ts or time.time()
        dq = self.events[entity]
        dq.append((ts, factor))
        while dq and (ts - dq[0][0] > self.window):
            dq.popleft()
        if len(dq) > MAX_EVENTS_PER_ENTITY:
            # Trim oldest excess
            while len(dq) > MAX_EVENTS_PER_ENTITY:
                dq.popleft()

    def recent(self, entity: str) -> List[str]:
        return [f for _, f in self.events.get(entity, [])]

    def match_patterns(self, entity: str) -> List[str]:
        factors = self.recent(entity)
        matches = []
        joined = ' '.join(factors)
        for name, seq in self.patterns:
            if all(s in joined for s in seq):
                matches.append(name)
        return matches

# Singleton (feature-flag controlled)
_SEQUENCER: TemporalSequencer | None = None

def get_sequencer() -> TemporalSequencer | None:
    import os
    if os.getenv('ENABLE_TEMPORAL_SEQUENCER','0').lower() in {'1','true','yes'}:
        global _SEQUENCER
        if _SEQUENCER is None:
            _SEQUENCER = TemporalSequencer()
        return _SEQUENCER
    return None

__all__ = ['TemporalSequencer','get_sequencer']
