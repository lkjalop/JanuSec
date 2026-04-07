"""persona_windows.py
====================
Persona-scoped evidence time window configuration.

These values control how far back each persona's evidence retrieval looks and
how strongly recent events are weighted vs older ones.  They can be overridden
at runtime via environment variables.

Usage:
    from src.core.configuration.persona_windows import PERSONA_EVIDENCE_WINDOWS, get_persona_window

The config is the 20/80 lever that changes reports from cosmetically different
to substantively different.  No schema changes required.
"""
from __future__ import annotations

import os
import json
from typing import TypedDict


class PersonaWindow(TypedDict):
    lookback_hours: int    # How far back to retrieve evidence
    recency_weight: float  # 0-1: emphasis on recent vs historical evidence
    max_events: int        # Cap on evidence items shown to this persona


# Default windows — can be fully replaced via PERSONA_WINDOWS_JSON env var
# or adjusted per-key via PERSONA_<PERSONA>_LOOKBACK_HOURS, etc.
_DEFAULTS: dict[str, PersonaWindow] = {
    "soc":          {"lookback_hours": 4,    "recency_weight": 0.85, "max_events": 20},
    "soc_analyst":  {"lookback_hours": 4,    "recency_weight": 0.85, "max_events": 20},
    "forensic":     {"lookback_hours": 72,   "recency_weight": 0.50, "max_events": 50},
    "forensics":    {"lookback_hours": 72,   "recency_weight": 0.50, "max_events": 50},
    "threat_hunter":{"lookback_hours": 720,  "recency_weight": 0.25, "max_events": 40},
    "ciso":         {"lookback_hours": 168,  "recency_weight": 0.30, "max_events": 15},
    "executive":    {"lookback_hours": 168,  "recency_weight": 0.20, "max_events": 10},
    "compliance":   {"lookback_hours": 2160, "recency_weight": 0.10, "max_events": 30},
    "audit":        {"lookback_hours": 2160, "recency_weight": 0.10, "max_events": 30},
}

# Allow full override via JSON env var
_ENV_JSON = os.getenv("PERSONA_WINDOWS_JSON")
if _ENV_JSON:
    try:
        _overrides = json.loads(_ENV_JSON)
        _DEFAULTS.update(_overrides)
    except Exception:
        pass

PERSONA_EVIDENCE_WINDOWS: dict[str, PersonaWindow] = _DEFAULTS


def get_persona_window(persona: str) -> PersonaWindow:
    """Return the window config for the given persona (case-insensitive).

    Falls back to a generous default so unknown personas still render cleanly.
    """
    key = (persona or "executive").lower().replace("-", "_").replace(" ", "_")
    return dict(PERSONA_EVIDENCE_WINDOWS.get(key) or PERSONA_EVIDENCE_WINDOWS.get("executive") or
                {"lookback_hours": 168, "recency_weight": 0.30, "max_events": 25})
