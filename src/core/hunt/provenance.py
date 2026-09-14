"""Hunt Provenance Utilities

Provides deterministic hashing for a hunt session's initiating parameters so
that replay equivalence can be asserted without relying on dynamic timestamps.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

PROVENANCE_VERSION = 1

def compute_session_hash(window_hours: int, model_enabled: bool, tenant: str, estimate_units: float, version_digest: str = "v0", extra: dict[str, Any] | None = None) -> str:
    payload = {
        'v': PROVENANCE_VERSION,
        'window_hours': window_hours,
        'model_enabled': model_enabled,
        'tenant': tenant,
        'estimate_units_rounded': round(estimate_units, 2),
        'version_digest': version_digest,
        'extra': extra or {}
    }
    blob = json.dumps(payload, sort_keys=True, separators=(',',':')).encode('utf-8')
    return hashlib.sha256(blob).hexdigest()
