from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class StageTiming:
    name: str
    duration_ms: float
    confidence_after: float
    factors_added: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    event_id: str
    stage: str
    confidence: float
    factors: list[str]
    processing_time: float
    stage_timings: list[dict[str, Any]] = field(default_factory=list)
    skipped_stages: list[str] = field(default_factory=list)
    metadata: dict[str, Any] | None = None
