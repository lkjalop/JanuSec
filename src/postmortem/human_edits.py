"""
Human edits layer — applies override diffs to section auto_output.

DESIGN
------
Auto-generated section output is FROZEN at transaction-time T0. Human edits
are stored as diffs in ``section.overrides``. The "computed view" at any
later time is ``apply_overrides_to_section(auto_output, overrides)``.

This pattern survives external auditor scrutiny because both records exist:
- "Platform said HIGH" → preserved in auto_output
- "Analyst overrode to MEDIUM with reason X" → preserved in overrides
- "Computed view shows MEDIUM" → what the rendered report displays

OVERRIDE SHAPE
--------------
Each override is a dict with:
  actor: str                  # who made the edit
  transaction_time: str       # ISO timestamp
  field_path: str             # dotted path into auto_output (e.g. "summary.failed_control_count")
  old_value: any              # what auto_output had at that path
  new_value: any              # what to display instead
  reason: str                 # mandatory free-text justification

Field paths use dotted notation. List indices use [N] syntax:
  "timeline[3].event"
  "by_framework.iso27001[0].severity"

ADD vs REPLACE vs DELETE
------------------------
Three operations supported via ``operation`` field on the override:
  "replace" (default): set value at field_path to new_value
  "add":     append new_value to a list at field_path
  "delete":  remove the element at field_path

Additions use ``new_value``; deletions ignore both old_value and new_value.
"""
from __future__ import annotations

import copy
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_INDEX_RE = re.compile(r"^([^\[]+)\[(\d+)\]$")


def apply_overrides_to_section(auto_output: Any, overrides: list[dict]) -> Any:
    """Apply a list of override diffs to a section's auto_output.

    Returns a new dict — does not mutate the input. Overrides are applied
    in order; later overrides on the same field path replace earlier ones.

    Tolerates malformed overrides (logs warning, skips).
    """
    if auto_output is None:
        # Stub section or failed section — overrides have nothing to apply to.
        return auto_output

    out = copy.deepcopy(auto_output)
    for ov in overrides or []:
        try:
            _apply_one(out, ov)
        except Exception as exc:
            logger.warning(
                "human_edits: skipping malformed override %s: %s",
                ov.get("field_path"), exc,
            )
    return out


def _apply_one(target: Any, override: dict) -> None:
    """Apply one override in place against ``target``."""
    op = (override.get("operation") or "replace").lower()
    field_path = override.get("field_path") or ""
    new_value = override.get("new_value")

    if not field_path:
        logger.warning("human_edits: override missing field_path: %s", override)
        return

    parts = _split_path(field_path)
    if not parts:
        return

    # Navigate to the parent container of the final path segment.
    parent = target
    for seg in parts[:-1]:
        parent = _step_into(parent, seg)
        if parent is None:
            return  # path doesn't exist; silently skip

    final = parts[-1]

    if op == "delete":
        _delete_at(parent, final)
    elif op == "add":
        _add_at(parent, final, new_value)
    else:  # replace (default)
        _replace_at(parent, final, new_value)


def _split_path(path: str) -> list[tuple[str, int | None]]:
    """Convert "a.b[2].c" → [('a', None), ('b', 2), ('c', None)]"""
    out: list[tuple[str, int | None]] = []
    for raw in path.split("."):
        m = _INDEX_RE.match(raw)
        if m:
            key, idx = m.group(1), int(m.group(2))
            out.append((key, idx))
        else:
            out.append((raw, None))
    return out


def _step_into(container: Any, seg: tuple[str, int | None]) -> Any:
    key, idx = seg
    if not isinstance(container, dict):
        return None
    nxt = container.get(key)
    if idx is not None:
        if not isinstance(nxt, list) or idx >= len(nxt):
            return None
        return nxt[idx]
    return nxt


def _replace_at(parent: Any, seg: tuple[str, int | None], new_value: Any) -> None:
    key, idx = seg
    if not isinstance(parent, dict):
        return
    if idx is None:
        parent[key] = new_value
    else:
        target_list = parent.get(key)
        if isinstance(target_list, list) and idx < len(target_list):
            target_list[idx] = new_value


def _add_at(parent: Any, seg: tuple[str, int | None], new_value: Any) -> None:
    key, idx = seg
    if not isinstance(parent, dict):
        return
    if idx is None:
        existing = parent.get(key)
        if isinstance(existing, list):
            existing.append(new_value)
        else:
            parent[key] = [new_value]


def _delete_at(parent: Any, seg: tuple[str, int | None]) -> None:
    key, idx = seg
    if not isinstance(parent, dict):
        return
    if idx is None:
        parent.pop(key, None)
    else:
        target_list = parent.get(key)
        if isinstance(target_list, list) and idx < len(target_list):
            target_list.pop(idx)


def append_override(
    section: dict,
    *,
    actor: str,
    field_path: str,
    new_value: Any,
    reason: str,
    operation: str = "replace",
    transaction_time: str | None = None,
) -> dict:
    """Helper to construct and append a well-formed override to a section.

    Captures the old_value snapshot so the auditor can see the diff later.
    """
    from datetime import datetime, timezone

    auto_output = section.get("auto_output") or {}
    parts = _split_path(field_path)
    cursor = auto_output
    old_value = None
    try:
        for seg in parts[:-1]:
            cursor = _step_into(cursor, seg)
            if cursor is None:
                break
        if cursor is not None and parts:
            key, idx = parts[-1]
            tmp = cursor.get(key) if isinstance(cursor, dict) else None
            if idx is not None and isinstance(tmp, list) and idx < len(tmp):
                old_value = tmp[idx]
            else:
                old_value = tmp
    except Exception:
        old_value = None

    override = {
        "actor":            actor,
        "transaction_time": transaction_time or datetime.now(timezone.utc).isoformat(),
        "operation":        operation,
        "field_path":       field_path,
        "old_value":        old_value,
        "new_value":        new_value,
        "reason":           reason,
    }
    section.setdefault("overrides", []).append(override)
    return override


__all__ = [
    "apply_overrides_to_section",
    "append_override",
]
