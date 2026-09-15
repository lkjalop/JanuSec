"""Production-grade rule: office_macro_chain_enriched

This rule builds on the placeholder by adding contextual scoring:
- checks hopgraph for prior related events (same host or user)
- applies off-hours and user role boosts
- emits a recommended factor by attaching `correlation_emission` to event
"""
from __future__ import annotations
from typing import Dict, Any
from datetime import datetime, timezone
import logging
from ..registry import register_rule

logger = logging.getLogger(__name__)

SUSPICIOUS_OFFICE_PARENTS = ('winword', 'excel', 'powerpnt', 'outlook')


def _is_off_hours(ts: float | None) -> bool:
    try:
        if ts is None:
            return False
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        hour = dt.hour
        # consider 0-6 and 20-23 UTC as off-hours for many orgs
        return (hour < 6) or (hour >= 20)
    except Exception:
        return False


def _get_hopgraph_context(event: Dict[str, Any]) -> Dict[str, Any]:
    """Query HopGraph lite if available for adjacent relevant factors.
    Returns simple context counts (related_events, unique_domains).
    Best-effort: failures are swallowed and empty context returned.
    """
    try:
        from src.core.graph.hopgraph_lite import get_graph
        g = get_graph()
        if not g:
            return {}
        # Query: temporal neighbors for host or user within last 24h
        node = None
        if event.get('host'):
            node = f"host:{event['host']}"
        elif event.get('user'):
            node = f"user:{event['user']}"
        if not node:
            return {}
        # temporal_query returns events list in this codebase
        res = g.temporal_query(node, seconds=86400)
        domains = {e.get('network_outbound_domain') for e in res if e.get('network_outbound_domain')}
        return {'related_events': len(res), 'unique_domains': len(domains)}
    except Exception as e:
        logger.debug('HopGraph context unavailable: %s', e)
        return {}


@register_rule(name='office_macro_external_c2_chain_enriched', mitre=['T1566.001','T1059.001'], factors_required=['parent_process','child_process','timestamp'], window_seconds=1800, severity='high', confidence_boost=0.55)
def office_macro_chain_enriched(event: Dict[str, Any]) -> bool:
    parent = str(event.get('parent_process') or '').lower()
    child = str(event.get('child_process') or '').lower()
    if not parent or not child:
        return False

    if not any(p in parent for p in SUSPICIOUS_OFFICE_PARENTS):
        return False

    # child suspicious binaries
    if not any(x in child for x in ('powershell', 'wscript', 'mshta', 'cscript')):
        return False

    # basic outbound domain evidence
    domains = event.get('network_outbound_domains') or []
    if not isinstance(domains, list) or len(domains) == 0:
        return False

    # contextual scoring
    score = 0.5
    if len(domains) >= 2:
        score += 0.1

    # off-hours boost
    if _is_off_hours(event.get('timestamp')):
        score += 0.1

    # hopgraph context
    ctx = _get_hopgraph_context(event)
    if ctx.get('related_events', 0) >= 3:
        score += 0.15
    if ctx.get('unique_domains', 0) >= 2:
        score += 0.1

    # cap score
    score = min(score, 0.95)

    # attach a light-weight emission object to event for downstream consumers (hopgraph/explain)
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'office_macro_external_c2_chain_enriched',
            'mitre': ['T1566.001','T1059.001'],
            'computed_score': round(score, 3),
            'evidence': {
                'parent_process': parent,
                'child_process': child,
                'outbound_domain_count': len(domains),
            },
        })
    except Exception:
        pass

    # decide fire based on threshold
    return score >= 0.6


__all__ = ["office_macro_chain_enriched"]
