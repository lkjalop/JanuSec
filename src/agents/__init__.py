"""
JanuSec Agentic Investigation Framework — Bounded Autonomy.

Structured agent loop: Planner → Investigator → Verifier → Narrator
with a hard autonomy boundary enforced by autonomy_gate.

Zone 0: BLOCKED   — never allowed (hardcoded deny list)
Zone 1: AUTO-OK   — read-only investigation actions
Zone 2: PROPOSE   — mutations require human approval
Zone 3: ESCALATE  — legal/regulatory, human must execute
"""
from __future__ import annotations

__all__ = [
    "ActionZone",
    "InvestigationContext",
    "AgentCycle",
]
