"""Evidence Envelope abstraction for Hunt Lanes.

Carries original event + accumulated contextual artifacts (factors, notes, attachments)
without mutating the underlying event dict. Lanes can append advisory factors and
lightweight metadata. Confidence deltas are disabled initially (advisory mode) and
can be enabled later via governance toggle.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LaneEmission:
    lane: str
    factors: list[str]
    notes: str | None = None
    latency_ms: float = 0.0

@dataclass
class EvidenceEnvelope:
    event: dict[str, Any]
    # Factors added by lanes (prefixed with lane name)
    lane_factors: list[str] = field(default_factory=list)
    emissions: list[LaneEmission] = field(default_factory=list)

    def add_emission(self, lane: str, factors: list[str], notes: str | None, latency_ms: float):
        # ensure lane prefix for governance clarity
        tagged = [f"lane_{lane}:{f}" for f in factors]
        self.lane_factors.extend(tagged)
        self.emissions.append(LaneEmission(lane=lane, factors=tagged, notes=notes, latency_ms=latency_ms))

    def export_hopgraph_signals(self) -> list[dict]:
        """Export emissions as lightweight hopgraph signals suitable for session builder ingestion.

        Returns list of dicts: {'lane': lane, 'factor': factor_name, 'tags':[], 'notes': notes}
        """
        out = []
        for e in self.emissions:
            for f in e.factors:
                # strip lane_ prefix if present
                name = f
                if name.startswith(f'lane_{e.lane}:'):
                    name = name.split(':',1)[1]
                out.append({'lane': e.lane, 'factor': name, 'notes': e.notes, 'latency_ms': e.latency_ms})
        return out

    @property
    def all_factors(self) -> list[str]:
        # Expose normalized factor names without the lane prefix for convenience in
        # unit tests and any legacy callers that only care about the emission key.
        # Callers that need the fully-qualified value should access lane_factors
        # directly.
        factors: list[str] = []
        for f in self.lane_factors:
            if ':' in f:
                factors.append(f.split(':', 1)[1])
            else:
                factors.append(f)
        return factors

class LaneContext:
    """Context object passed to each lane; provides timing and shared caches later."""
    def __init__(self):
        self.start = time.perf_counter()

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self.start) * 1000
