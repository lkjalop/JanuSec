from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class ProcessingResult:
    """Result of event processing with full audit trail."""
    event_id: str
    verdict: str
    confidence: float
    processing_time_ms: float
    factors: List[str]
    stage_timings: List[Dict[str, object]]
    config_digests: Dict[str, str]
    custody_hash: str
