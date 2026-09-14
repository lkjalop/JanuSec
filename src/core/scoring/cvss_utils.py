"""Lightweight CVSS temporal/environmental helpers.

This module provides small helpers to compute adjusted scores. For full
CVSS parsing consider using a library; this is intentionally tiny to
support unit tests and demonstration.
"""
from typing import Dict, Any


def adjust_cvss(base_score: float, temporal_factor: float | None = None, env_modifier: float | None = None) -> float:
    """Adjust a CVSS base score by temporal and environmental multipliers.

    - `temporal_factor` is typically in [0.0, 1.0] representing exploit maturity.
    - `env_modifier` is a multiplier reflecting asset exposure/controls.
    """
    score = float(base_score or 0.0)
    if temporal_factor is not None:
        score = score * float(temporal_factor)
    if env_modifier is not None:
        score = min(10.0, score * float(env_modifier))
    return round(score, 2)


def map_cvss_to_exploitability(score: float) -> float:
    """Map a CVSS-like score into an exploitability influence 0-10."""
    # simple linear mapping for now
    return round(min(10.0, max(0.0, (score / 10.0) * 10.0)), 2)
