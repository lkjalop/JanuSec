"""State-singleton invariants — the net for the app.py state-extraction work.

The dual-instance bug: a confirmed-breach decision written via one module path is
invisible via another (separate DECISION_CACHE dicts created by the
`except: DECISION_CACHE = {}` fallback during circular imports). These tests pin the
invariant — ONE decision cache, reachable identically from every consumer — so any
extraction step that reintroduces a second instance fails immediately.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.acceptance


def test_accessor_returns_canonical_instance():
    from src.api.runtime_state import get_decision_cache, DECISION_CACHE
    assert get_decision_cache() is DECISION_CACHE


def test_all_runtime_state_paths_resolve_same_object():
    import importlib
    objs = []
    for name in ("src.api.runtime_state", "api.runtime_state"):
        try:
            objs.append(importlib.import_module(name).DECISION_CACHE)
        except Exception:
            pass
    assert objs, "runtime_state not importable"
    first = objs[0]
    for o in objs[1:]:
        assert o is first, "src.api.runtime_state and api.runtime_state hold DIFFERENT DECISION_CACHE objects"


def test_write_visible_across_accessor_and_aggregate():
    # A decision written through the record path MUST be visible both via the accessor
    # and via the report aggregation path — no instance can swallow it.
    from src.api.runtime_state import get_decision_cache
    from src.api.server import _record_decision
    from src.api.report_aggregation import aggregate_decisions

    get_decision_cache().clear()
    _record_decision("singleton-probe-1", "VALIDATED_BREACH", 0.91, ["iam:kerberoasting"])
    assert "singleton-probe-1" in get_decision_cache()
    flagged = aggregate_decisions().get("flagged_events") or []
    assert any(e.get("event_id") == "singleton-probe-1" for e in flagged), (
        "decision written via _record_decision is invisible to aggregate_decisions "
        "(a second DECISION_CACHE instance swallowed it)")
