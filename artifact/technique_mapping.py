"""Compatibility shim for legacy imports.

The canonical implementation lives under ``src.artifact.technique_mapping``.
Older tests still import ``artifact.technique_mapping`` directly, so delegate
instead of returning the input unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List

from src.artifact.technique_mapping import apply_mapping as _apply_mapping


def apply_mapping(obs: Dict[str, Any] | List[str]) -> Dict[str, Any]:
    return _apply_mapping(obs)


__all__ = ["apply_mapping"]
