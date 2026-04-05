from __future__ import annotations
from typing import Dict, Any
from datetime import datetime, timezone
from ..registry import register_rule

LOL_BINS = ('mshta','wscript','cscript','rundll32','regsvr32')


def _is_off_hours(ts: float | None) -> bool:
    try:
        if ts is None:
            return False
        hour = datetime.fromtimestamp(float(ts), tz=timezone.utc).hour
        return (hour < 6) or (hour >= 20)
    except Exception:
        return False


@register_rule(name='scheduled_task_lolbin_anomaly_enriched', mitre=['T1053'], factors_required=['process','command_line','timestamp'], window_seconds=3600, severity='high', confidence_boost=0.45)
def scheduled_task_lolbin_enriched(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    cmd = str(event.get('command_line') or '')
    if not proc or not cmd:
        return False
    if 'schtasks' not in proc and 'at.exe' not in proc:
        return False

    if not any(b in cmd.lower() for b in LOL_BINS):
        return False

    score = 0.55
    if '/sc minute' in cmd.lower() or '/sc once' in cmd.lower():
        score += 0.05
    if _is_off_hours(event.get('timestamp')):
        score += 0.1

    score = min(score, 0.95)
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'scheduled_task_lolbin_anomaly_enriched',
            'mitre': ['T1053'],
            'computed_score': round(score, 3),
            'evidence': {'proc': proc},
        })
    except Exception:
        pass
    return score >= 0.6


__all__ = ["scheduled_task_lolbin_enriched"]
