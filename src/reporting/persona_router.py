"""Batch persona routing — bridges tiered_triage output to persona_views.

Given a ``TriageResult``, generates persona-specific views for every alert
in each persona queue, respecting the disclosure level assigned by the triage
engine.  The analyst gate is checked before generating Tier-2 level views;
gated alerts that are still PENDING get a minimal "awaiting approval" stub
instead of the full deep-dive.

Usage::

    from src.reporting.persona_router import route_personas

    views = route_personas(triage_result, report_lookup)
    # views == { 'executive': [...], 'soc_analyst': [...], ... }
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from src.reporting.tiered_triage import TriageResult
from src.reporting.analyst_gate import get_analyst_gate, GateState
from src.reporting.persona_views import generate_persona_view

logger = logging.getLogger(__name__)


def route_personas(
    triage: TriageResult,
    report_lookup: Dict[str, Dict[str, Any]] | Callable[[str], Dict[str, Any] | None] | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Generate persona views for every alert in each persona queue.

    Parameters
    ----------
    triage
        Output of ``triage_alerts()``.
    report_lookup
        Either a ``dict[alert_id -> full_report]`` or a callable that
        returns the full report dict for a given alert_id.
        If ``None``, the raw alert dictionary stored on ``ScoredAlert.raw``
        is used directly.

    Returns
    -------
    dict mapping persona name -> list of persona-view dicts.
    """

    gate = get_analyst_gate()
    persona_views: Dict[str, List[Dict[str, Any]]] = {}

    # Build a quick lookup of alert_id → ScoredAlert from the triage tiers
    alert_map: Dict[str, Any] = {}
    for tier_list in triage.tiers.values():
        for sa in tier_list:
            alert_map[sa.alert_id] = sa

    for persona, queue_items in triage.persona_queues.items():
        views: List[Dict[str, Any]] = []

        for item in queue_items:
            alert_id = item['alert_id']
            disclosure_level = item.get('disclosure_level', 2)
            tier = item.get('tier', 'P3')

            # Resolve the full report
            report = _resolve_report(alert_id, alert_map, report_lookup)
            if report is None:
                continue

            # Check analyst gate for P1/P2 — if still PENDING, generate
            # a minimal stub instead of the full persona view
            if tier in ('P1', 'P2') and not gate.is_approved(alert_id):
                entry = gate.status(alert_id)
                state = entry.state.value if entry else 'UNKNOWN'
                views.append({
                    'alert_id': alert_id,
                    'persona': persona,
                    'tier': tier,
                    'gate_state': state,
                    'disclosure_level': 0,
                    'headline': f'Alert {alert_id} awaiting analyst approval ({state})',
                    'priority_score': item.get('priority_score', 0),
                })
                continue

            # Annotate report with tier metadata for persona view enrichment
            report_for_view = dict(report)
            report_for_view['tier_metadata'] = {
                'tier': tier,
                'priority_score': item.get('priority_score', 0),
                'score_breakdown': item.get('score_breakdown', {}),
            }

            try:
                view = generate_persona_view(
                    report_for_view,
                    persona=persona,
                    disclosure_level=disclosure_level,
                )
                # Attach triage context for UI rendering
                view['tier'] = tier
                view['priority_score'] = item.get('priority_score', 0)
                view['gate_state'] = 'APPROVED'
                views.append(view)
            except Exception:
                logger.warning('Failed to generate persona view for %s / %s', persona, alert_id, exc_info=True)

        persona_views[persona] = views

    return persona_views


def _resolve_report(
    alert_id: str,
    alert_map: Dict[str, Any],
    report_lookup: Dict[str, Dict[str, Any]] | Callable | None,
) -> Dict[str, Any] | None:
    """Resolve the full report dict for an alert_id."""
    # Try callable lookup first
    if callable(report_lookup):
        result = report_lookup(alert_id)
        if result is not None:
            return result

    # Try dict lookup
    if isinstance(report_lookup, dict):
        result = report_lookup.get(alert_id)
        if result is not None:
            return result

    # Fall back to ScoredAlert.raw
    sa = alert_map.get(alert_id)
    if sa is not None:
        return sa.raw

    return None
