"""
Threshold Jitter (P0-C)
Adds calibrated Gaussian noise to pipeline score thresholds to make adaptive
evasion attacks harder.  Each call produces a fresh ephemeral threshold value
so an attacker cannot fingerprint the exact cut-off by probing repeatedly.

Usage:
    from src.security.threshold_jitter import get_jittered_threshold, JITTER_ENABLED

    effective_threshold = get_jittered_threshold(base=0.60)
    if score >= effective_threshold:
        ...
"""
from __future__ import annotations

import logging
import os
import random

logger = logging.getLogger(__name__)

# Feature flag — set THRESHOLD_JITTER_ENABLED=0 to disable without code change
JITTER_ENABLED: bool = os.getenv('THRESHOLD_JITTER_ENABLED', '1') not in ('0', 'false', 'no')

# Default sigma (std-dev) for the Gaussian noise.  Override with THRESHOLD_JITTER_SIGMA.
_DEFAULT_SIGMA: float = float(os.getenv('THRESHOLD_JITTER_SIGMA', '0.015'))

# Hard absolute limits for clamping — regardless of base, never go outside these.
_ABS_MIN: float = 0.20
_ABS_MAX: float = 0.95

# Per-stage baseline thresholds (used as defaults when callers don't supply a base).
BASE_THRESHOLDS: dict[str, float] = {
    'beacon':         float(os.getenv('BEACON_SCORE_THRESHOLD',        '0.60')),
    'egress':         float(os.getenv('EGRESS_SCORE_THRESHOLD',        '0.55')),
    'rare_token':     float(os.getenv('RARE_TOKEN_SCORE_THRESHOLD',    '0.65')),
    'domain_novelty': float(os.getenv('DOMAIN_NOVELTY_SCORE_THRESHOLD','0.70')),
    'triage':         float(os.getenv('LLM_T1_MIN_TRIAGE',            '0.15')),
    'incident_autogen': float(os.getenv('INCIDENT_AUTOGEN_SCORE_THRESHOLD', '0.80')),
}


def get_jittered_threshold(
    base: float,
    sigma: float = _DEFAULT_SIGMA,
    *,
    max_delta: float = 0.15,
) -> float:
    """Return ``base`` perturbed by Gaussian noise, clamped within safe limits.

    Args:
        base:      The nominal threshold value (e.g. 0.60).
        sigma:     Standard deviation of the noise (default 0.015).
        max_delta: Maximum absolute deviation allowed from base (default 0.15).

    Returns:
        Effective threshold value in [abs_min, abs_max].
    """
    if not JITTER_ENABLED:
        return base

    noise = random.gauss(0.0, sigma)
    # Clamp to ±max_delta around base, then to absolute limits
    effective = base + max(-max_delta, min(max_delta, noise))
    effective = max(_ABS_MIN, min(_ABS_MAX, effective))
    return effective


def get_stage_threshold(stage: str, sigma: float = _DEFAULT_SIGMA) -> float:
    """Convenience wrapper: look up the base for *stage* and jitter it.

    Falls back to 0.60 if the stage is unknown.
    """
    base = BASE_THRESHOLDS.get(stage, 0.60)
    return get_jittered_threshold(base, sigma=sigma)
