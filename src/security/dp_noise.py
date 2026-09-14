"""
Differential Privacy Output Noise (P2)
Adds calibrated noise to confidence scores and sensitive counts returned in
API responses to prevent membership inference attacks.  An adversary who
can repeatedly query the API with crafted inputs and observe precise confidence
values can infer whether similar events are in the training/baseline data.

Two protection mechanisms:
  1. Quantisation — snap confidence to the nearest band (e.g. 5%, 10%)
  2. Laplace noise  — add Laplace-distributed noise before quantisation
     (provides ε-differential privacy when ε is configured)

Env vars:
    DP_ENABLED              — '1' to enable (default '1')
    DP_QUANTISE_BANDS       — number of output bands (default 20 = 5% resolution)
    DP_LAPLACE_EPSILON      — ε for Laplace noise (default 1.0; lower=more noise)
    DP_LAPLACE_SENSITIVITY  — global sensitivity Δf (default 0.1)
    DP_PROTECTED_FIELDS     — comma-separated field names to apply noise to
                              (default 'confidence,score,triage_score,risk_score')
"""
from __future__ import annotations

import logging
import math
import os
import random
from typing import Any

logger = logging.getLogger(__name__)

_ENABLED = os.getenv('DP_ENABLED', '1') not in ('0', 'false', 'no')
_BANDS = max(2, int(os.getenv('DP_QUANTISE_BANDS', '20')))  # 20 bands → 5% resolution
_EPSILON = float(os.getenv('DP_LAPLACE_EPSILON', '1.0'))
_SENSITIVITY = float(os.getenv('DP_LAPLACE_SENSITIVITY', '0.1'))
_PROTECTED_FIELDS = set(
    os.getenv(
        'DP_PROTECTED_FIELDS',
        'confidence,score,triage_score,risk_score,correlation_score,factor_score',
    ).split(',')
)


def _laplace_noise(epsilon: float, sensitivity: float) -> float:
    """Sample ε-DP Laplace noise: scale = sensitivity / epsilon."""
    scale = sensitivity / max(epsilon, 1e-9)
    # Using the inverse CDF method for Laplace distribution
    u = random.uniform(-0.5, 0.5)
    return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))


def quantise(value: float, bands: int = _BANDS) -> float:
    """Snap a [0,1] float to the nearest 1/bands boundary."""
    if bands <= 1:
        return value
    band_width = 1.0 / bands
    return round(round(value / band_width) * band_width, 4)


def add_noise(value: float, epsilon: float = _EPSILON, sensitivity: float = _SENSITIVITY) -> float:
    """Add Laplace noise then quantise to produce a DP-protected score."""
    if not _ENABLED:
        return value
    noised = value + _laplace_noise(epsilon, sensitivity)
    noised = max(0.0, min(1.0, noised))  # clamp to [0,1]
    return quantise(noised)


def protect_confidence(raw_confidence: float) -> float:
    """Public API: apply DP protection to a confidence score in [0,1]."""
    return add_noise(raw_confidence)


def protect_dict(data: dict, fields: set[str] | None = None) -> dict:
    """Return a shallow copy of *data* with DP noise applied to protected fields.

    Only keys in *fields* (default: _PROTECTED_FIELDS) are modified.
    Nested dicts are handled one level deep.
    """
    if not _ENABLED:
        return data

    target_fields = fields or _PROTECTED_FIELDS
    result = {}
    for k, v in data.items():
        if k in target_fields and isinstance(v, (int, float)):
            result[k] = add_noise(float(v))
        elif isinstance(v, dict):
            # One level of recursion for nested score objects
            result[k] = protect_dict(v, target_fields)
        else:
            result[k] = v
    return result


def protect_list_of_dicts(items: list[dict], fields: set[str] | None = None) -> list[dict]:
    """Apply protect_dict to every item in a list."""
    return [protect_dict(item, fields) for item in items]


def verdict_to_tier(value: float) -> str:
    """Convert a noised confidence to a coarse tier label (alternative to raw scores)."""
    # Quantise to 3 public tiers — maximum evasion resistance
    if value >= 0.70:
        return 'HIGH'
    if value >= 0.40:
        return 'MEDIUM'
    return 'LOW'
