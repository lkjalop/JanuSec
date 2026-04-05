from __future__ import annotations
from typing import Dict, Any
from datetime import datetime, timezone
from ..registry import register_rule


def _is_off_hours(ts: float | None) -> bool:
    try:
        if ts is None:
            return False
        hour = datetime.fromtimestamp(float(ts), tz=timezone.utc).hour
        return (hour < 6) or (hour >= 20)
    except Exception:
        return False


@register_rule(name='persistence_new_service_nonstandard_enriched', mitre=['T1543'], factors_required=['service_name','binary_path','timestamp'], window_seconds=3600, severity='high', confidence_boost=0.5)
def new_service_nonstandard_enriched(event: Dict[str, Any]) -> bool:
    path = str(event.get('binary_path') or '').lower()
    if not path:
        return False
    suspicious = ('\\temp\\' in path) or ('\\users\\' in path and '\\appdata\\' in path) or (path.endswith('.js') or path.endswith('.vbs'))
    if not suspicious:
        return False

    score = 0.55
    if _is_off_hours(event.get('timestamp')):
        score += 0.1
    if any(x in path for x in ('\\downloads\\', '\\appdata\\local\\temp\\')):
        score += 0.1

    score = min(score, 0.95)
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'persistence_new_service_nonstandard_enriched',
            'mitre': ['T1543'],
            'computed_score': round(score, 3),
            'evidence': {'binary_path': path},
        })
    except Exception:
        pass
    return score >= 0.6


__all__ = ["new_service_nonstandard_enriched"]
