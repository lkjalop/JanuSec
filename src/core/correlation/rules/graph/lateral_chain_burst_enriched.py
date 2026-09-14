from __future__ import annotations
from typing import Dict, Any
from datetime import datetime, timezone
from ..registry import register_rule


@register_rule(name='lateral_chain_burst_enriched', mitre=['T1021'], factors_required=['source_host','dest_host','timestamp'], window_seconds=600, severity='high', confidence_boost=0.5)
def lateral_chain_burst_enriched(event: Dict[str, Any]) -> bool:
    """Detect bursts of lateral movement between hosts; boost when many destinations seen."""
    src = str(event.get('source_host') or '').lower()
    dst = str(event.get('dest_host') or '').lower()
    if not src or not dst:
        return False

    # simple heuristic: if event carries lateral_count in window, consider
    count = int(event.get('lateral_count_in_window') or 0)
    score = 0.4
    if count >= 3:
        score += 0.3
    elif count == 2:
        score += 0.15

    # off-hours
    try:
        ts = event.get('timestamp')
        if ts and (datetime.fromtimestamp(float(ts), tz=timezone.utc).hour < 6):
            score += 0.1
    except Exception:
        pass

    score = min(score, 0.95)
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'lateral_chain_burst_enriched',
            'mitre': ['T1021'],
            'computed_score': round(score, 3),
            'evidence': {'src': src, 'dst': dst, 'count': count},
        })
    except Exception:
        pass

    return score >= 0.6
