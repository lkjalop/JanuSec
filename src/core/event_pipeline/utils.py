from __future__ import annotations

from typing import Any


def cfg_get(container: Any, key: str, default: Any):
    """Dictionary-style .get that tolerates plain objects."""
    if hasattr(container, 'get'):
        try:
            return container.get(key, default)
        except Exception:
            return default
    if isinstance(container, dict):
        return container.get(key, default)
    return default
