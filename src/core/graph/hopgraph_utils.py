"""Helpers for HopGraph canonical IDs and attribute merging policies.

Provides `canonical_node_id` and `merge_attrs` used by consumers to upsert/merge
attributes into HopGraph nodes consistently.
"""
from __future__ import annotations
from typing import Any, Dict
import time


def canonical_node_id(node_type: str, identifier: str) -> str:
    """Return a stable canonical node id for a given node type and identifier.

    Example: canonical_node_id('file_hash', 'deadbeef') -> 'file_hash:deadbeef'
    """
    return f"{node_type}:{identifier}"


def _merge_dict(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    # shallow merge, prefer src values when non-empty
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            dst[k] = _merge_dict(dict(dst.get(k)), v)
        else:
            # prefer non-None/empty src values
            if v is not None and v != '':
                dst[k] = v
    return dst


def merge_attrs(existing: Dict[str, Any] | None, new: Dict[str, Any], *, prefer_new=True) -> Dict[str, Any]:
    """Merge two attribute dicts deterministically.

    - existing: prior attributes (may be None)
    - new: incoming attributes
    - prefer_new: when True, prefer `new` values when conflicts occur.

    The merge strategy is shallow-recursive: nested dicts merged recursively.
    For conflicting scalar values, prefer `new` when `prefer_new` True, else keep `existing`.
    """
    if existing is None:
        return dict(new or {})
    if new is None:
        return dict(existing or {})
    res = dict(existing)
    if prefer_new:
        res = _merge_dict(res, new)
    else:
        # prefer existing: only copy values present in existing; add missing from new
        for k, v in new.items():
            if k not in res or res.get(k) is None:
                res[k] = v
    return res


__all__ = ['canonical_node_id', 'merge_attrs']


def safe_upsert_node(hg, node_type: str, identifier: str, attrs: dict | None, source: str = 'unknown') -> None:
    """Safely upsert/merge a node into a HopGraph-like object.

    - `hg` is the hopgraph instance (may provide `upsert_node`, `merge_node_attrs`, `get_node`, or `ingest_event`).
    - This helper centralizes canonical id creation and merge logic.
    """
    node_id = canonical_node_id(node_type, identifier)
    attrs = attrs or {}
    try:
        if hasattr(hg, 'upsert_node'):
            try:
                if hasattr(hg, 'get_node') and callable(getattr(hg, 'get_node')):
                    existing = hg.get_node(node_id) or {}
                    merged = merge_attrs(existing.get('attrs', {}), attrs)
                else:
                    merged = attrs
                hg.upsert_node(node_id, node_type=node_type, attrs=merged, source=source)
                return
            except Exception:
                # fall through to other methods
                pass
        if hasattr(hg, 'merge_node_attrs'):
            try:
                hg.merge_node_attrs(node_id, attrs, source=source)
                return
            except Exception:
                pass
        if hasattr(hg, 'ingest_event'):
            try:
                # Build a minimal ingest_event payload
                ev = {'nodes': [{'id': node_id, 'type': node_type, 'attrs': attrs}], 'edges': []}
                hg.ingest_event(ev, source=source)
                return
            except Exception:
                pass
    except Exception:
        # Last-resort: ignore failures to avoid causing pipeline crashes
        return
