from __future__ import annotations
from typing import Dict, Any
from datetime import datetime, timezone
from ..registry import register_rule


@register_rule(
    name='net_beacon_low_freq_enriched',
    mitre=['T1043'],
    factors_required=['dst_ip', 'beacon_interval', 'timestamp'],
    window_seconds=3600,
    severity='medium',
    confidence_boost=0.35,
)
def net_beacon_low_freq_enriched(event: Dict[str, Any]) -> bool:
    interval = event.get('beacon_interval')
    if not interval:
        return False
    try:
        iv = float(interval)
    except Exception:
        return False

    score = 0.3
    # periodic intervals near known C2 cadence (e.g., 300s) increase score
    if abs(iv - 300.0) <= 30:
        score += 0.25
    # off-hours increase
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
            'rule': 'net_beacon_low_freq_enriched',
            'mitre': ['T1043'],
            'computed_score': round(score, 3),
            'evidence': {'interval': iv},
        })
    except Exception:
        pass

    return score >= 0.5
