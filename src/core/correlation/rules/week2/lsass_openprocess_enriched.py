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


SUSPICIOUS_CALLERS = (
    'mimikatz', 'procdump', 'taskmgr', 'rundll32', 'wmic', 'powershell'
)


@register_rule(name='cred_lsass_openprocess_enriched', mitre=['T1003'], factors_required=['target_process','caller_process','timestamp'], window_seconds=600, severity='critical', confidence_boost=0.7)
def lsass_openprocess_enriched(event: Dict[str, Any]) -> bool:
    tgt = str(event.get('target_process') or '').lower()
    caller = str(event.get('caller_process') or '').lower()
    if 'lsass.exe' not in tgt or not caller:
        return False
    if caller in ('lsass.exe', 'services.exe'):
        return False

    score = 0.7
    if any(s in caller for s in SUSPICIOUS_CALLERS):
        score += 0.15
    if _is_off_hours(event.get('timestamp')):
        score += 0.1

    score = min(score, 0.99)
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'cred_lsass_openprocess_enriched',
            'mitre': ['T1003'],
            'computed_score': round(score, 3),
            'evidence': {'caller_process': caller, 'target': tgt},
        })
    except Exception:
        pass
    return score >= 0.75


__all__ = ["lsass_openprocess_enriched"]
