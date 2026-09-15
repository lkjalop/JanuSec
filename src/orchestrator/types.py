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
    factors: list[str]
    stage_timings: list[dict[str, object]]
    config_digests: dict[str, str]
    custody_hash: str
