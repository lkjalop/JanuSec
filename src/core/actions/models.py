"""Action decision models"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any
import time

@dataclass
class ActionDecision:
    event_id: str
    tenant_id: str | None
    decision: str  # allow|block|escalate|sim_block
    reasons: List[str]
    severity: float | None = None
    quality: float | None = None
    factors: List[str] = field(default_factory=list)
    risk_context: float | None = None
    ts: float = field(default_factory=lambda: time.time())
