"""Action decision models"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ActionDecision:
    event_id: str
    tenant_id: str | None
    decision: str  # allow|block|escalate|sim_block
    reasons: list[str]
    severity: float | None = None
    quality: float | None = None
    factors: list[str] = field(default_factory=list)
    risk_context: float | None = None
    ts: float = field(default_factory=lambda: time.time())
