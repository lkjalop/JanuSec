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


@register_rule(name='powershell_encoded_command_enriched', mitre=['T1059.001'], factors_required=['command_line','timestamp'], window_seconds=900, severity='high', confidence_boost=0.5)
def powershell_encoded_enriched(event: Dict[str, Any]) -> bool:
    cmd = str(event.get('command_line') or '')
    if not cmd:
        return False
    lower = cmd.lower()
    if ('powershell' not in lower and 'pwsh' not in lower) or ('-enc' not in lower and '-encodedcommand' not in lower):
        return False

    score = 0.6
    # longer command line tends to be more suspicious in this heuristic
    if len(cmd) > 180:
        score += 0.1
    if _is_off_hours(event.get('timestamp')):
        score += 0.1

    score = min(score, 0.95)
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'powershell_encoded_command_enriched',
            'mitre': ['T1059.001'],
            'computed_score': round(score, 3),
            'evidence': {'cmd_length': len(cmd)},
        })
    except Exception:
        pass
    return score >= 0.65


__all__ = ["powershell_encoded_enriched"]
