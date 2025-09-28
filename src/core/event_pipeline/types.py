from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class StageTiming:
    name: str
    duration_ms: float
    confidence_after: float
    factors_added: List[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    event_id: str
    stage: str
    confidence: float
    factors: List[str]
    processing_time: float
    stage_timings: List[Dict[str, Any]] = field(default_factory=list)
    skipped_stages: List[str] = field(default_factory=list)

