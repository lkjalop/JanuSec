from __future__ import annotations

"""Global registry to enforce uniqueness of factor sources across scopes.

Uniqueness key: (technique_id, rule_name, scope). Used by:
  - Correlation rule registry (scope='correlation')
  - Hunt lanes (scope='hunt_lane')

On duplicate registrations, raises ValueError to fail fast at load time.
Intended to be imported by registries at registration time.
"""

from typing import Optional, Tuple, Set
import threading

_LOCK = threading.Lock()
_SEEN: Set[Tuple[str, str, str]] = set()


def register_source(technique_id: Optional[str], rule_name: str, scope: str) -> None:
    """Register a source tuple; raise on duplicate.

    technique_id: canonical technique (e.g., 'T1059') or a placeholder like 'LANE'.
    rule_name: correlation rule name or lane name.
    scope: one of {'correlation','hunt_lane','other'}.
    """
    key = (str(technique_id or 'NONE'), str(rule_name), str(scope))
    with _LOCK:
        if key in _SEEN:
            raise ValueError(f"Duplicate factor source detected: {key}")
        _SEEN.add(key)


def reset_for_tests() -> None:  # pragma: no cover
    with _LOCK:
        _SEEN.clear()


__all__ = ["register_source", "reset_for_tests"]

