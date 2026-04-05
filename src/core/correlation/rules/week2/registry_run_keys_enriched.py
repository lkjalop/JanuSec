from __future__ import annotations
from typing import Dict, Any
from datetime import datetime, timezone
from ..registry import register_rule


RUN_KEYS = (
    '\\software\\microsoft\\windows\\currentversion\\run',
    '\\software\\microsoft\\windows\\currentversion\\runonce'
)


def _is_off_hours(ts: float | None) -> bool:
    try:
        if ts is None:
            return False
        hour = datetime.fromtimestamp(float(ts), tz=timezone.utc).hour
        return (hour < 6) or (hour >= 20)
    except Exception:
        return False


@register_rule(name='persistence_registry_run_key_enriched', mitre=['T1547.001'], factors_required=['registry_key','process','timestamp'], window_seconds=3600, severity='high', confidence_boost=0.5)
def registry_run_key_enriched(event: Dict[str, Any]) -> bool:
    key = str(event.get('registry_key') or '').lower()
    proc = str(event.get('process') or '').lower()
    if not key or not proc:
        return False
    if not any(k in key for k in RUN_KEYS):
        return False

    score = 0.55
    if any(b in proc for b in ('powershell', 'reg.exe', 'regedit')):
        score += 0.1
    if _is_off_hours(event.get('timestamp')):
        score += 0.1

    score = min(score, 0.95)
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'persistence_registry_run_key_enriched',
            'mitre': ['T1547.001'],
            'computed_score': round(score, 3),
            'evidence': {'registry_key': key},
        })
    except Exception:
        pass
    return score >= 0.6


__all__ = ["registry_run_key_enriched"]
