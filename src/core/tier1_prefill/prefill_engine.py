"""Tier-1 prefill engine — thin compatibility shim.

All logic has moved to focused submodules. Import from this module
continues to work for backward compatibility.
"""
from .evidence_binder import *   # noqa: F401,F403
from .threat_models import *     # noqa: F401,F403
from .verdict_engine import *    # noqa: F401,F403
from .prefill_orchestrator import *  # noqa: F401,F403
# Explicit re-exports for the two public entry points
from .prefill_orchestrator import run_prefill, run_single_cluster_prefill  # noqa: F401
from .prefill_orchestrator import (  # noqa: F401
    _ensure_v2_prefill_fields,
    _fallback_incident_name,
    _infer_root_cause,
    _parse_prefill_json,
)
from .evidence_binder import (  # noqa: F401
    _build_entity_cluster_index,
    _compute_cross_cluster_links,
    _extract_entity_set,
    _get_rows_for_cluster,
    _row_action_text,
)
from .threat_models import _compute_confidence_meter  # noqa: F401
from .verdict_engine import _validate_entity_pins  # noqa: F401
from . import prefill_orchestrator as _prefill_orchestrator

import threading as _threading

_ORIG_BUILD_EVENT_CHAIN_SUMMARY = _prefill_orchestrator._build_event_chain_summary
_ORIG_COMPUTE_DREAD_SCORE = _prefill_orchestrator._compute_dread_score
_MONKEY_PATCH_LOCK = _threading.Lock()


def _build_event_chain_summary(cluster, rows):  # noqa: D401
    return _ORIG_BUILD_EVENT_CHAIN_SUMMARY(cluster, rows)


def _compute_dread_score(cluster, rows):  # noqa: D401
    return _ORIG_COMPUTE_DREAD_SCORE(cluster, rows)


def _enrich_cluster_intelligence(data, cluster, rows) -> None:
    """Compatibility wrapper whose helpers remain monkeypatchable on this shim.

    Thread-safe: holds _MONKEY_PATCH_LOCK across the swap so concurrent
    prefill jobs cannot observe a partially-swapped orchestrator state.
    """
    with _MONKEY_PATCH_LOCK:
        old_event = _prefill_orchestrator._build_event_chain_summary
        old_dread = _prefill_orchestrator._compute_dread_score
        _prefill_orchestrator._build_event_chain_summary = globals()['_build_event_chain_summary']
        _prefill_orchestrator._compute_dread_score = globals()['_compute_dread_score']
        try:
            return _prefill_orchestrator._enrich_cluster_intelligence(data, cluster, rows)
        finally:
            _prefill_orchestrator._build_event_chain_summary = old_event
            _prefill_orchestrator._compute_dread_score = old_dread

_SHIM_PLACEHOLDER = True  # sentinel so legacy importers can detect the shim
