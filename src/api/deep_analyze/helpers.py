"""Pure text/data helper utilities for the deep-analysis pipeline.

Zero external dependencies beyond stdlib. Safe to import from anywhere.
"""
from __future__ import annotations

import json
from typing import Any


def _safe_text(value: Any) -> str:
    if value is None:
        return ''
    return str(value).strip()


def _nested_get(obj: Any, dotted_path: str) -> Any:
    """Resolve a dotted path through nested dicts/lists (e.g. 'actor.alternateId').

    Integer path segments index into lists. Returns None if any step is missing.
    """
    parts = dotted_path.split('.')
    current = obj
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _collect_strings_from_row(row: dict) -> str:
    try:
        return json.dumps(row, default=str)
    except Exception:
        return str(row)
