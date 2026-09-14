from __future__ import annotations

import hashlib
from typing import Optional
from src.repositories.ab_test_repo import assign_variant, get_test

# In-memory registry of enabled auto-assign tests: test_id -> rollout_pct
_ENABLED: dict[str, int] = {}


def enable_test(test_id: str, rollout_pct: int = 10):
    _ENABLED[test_id] = int(rollout_pct)


def disable_test(test_id: str):
    _ENABLED.pop(test_id, None)


def is_enabled(test_id: str) -> bool:
    return test_id in _ENABLED


async def assign_if_enabled(test_id: str, subject_id: str, tenant_id: Optional[str] = None) -> Optional[str]:
    """Deterministically assign variant for subject_id if test is enabled.
    Persists assignment via ab_test_repo.assign_variant.
    Returns variant or None if test not enabled.
    """
    if test_id not in _ENABLED:
        return None
    pct = _ENABLED[test_id]
    # deterministic local hash assignment
    h = hashlib.sha256((subject_id + test_id).encode('utf-8')).digest()
    v = int.from_bytes(h[:2], 'big') % 100
    variant = 'B' if v < pct else 'A'
    await assign_variant(test_id, tenant_id, subject_id, variant)
    return variant
