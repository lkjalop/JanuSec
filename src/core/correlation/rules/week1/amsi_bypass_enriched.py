from __future__ import annotations
from typing import Dict, Any
import re
from datetime import datetime, timezone
from ..registry import register_rule

_AMSI_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"AmsiUtils",
        r"AmsiScanBuffer",
        r"AMSIInitFailed",
        r"System\.Management\.Automation",
        r"FromBase64String\([A-Za-z0-9+/=]{20,}",
    ]
]


def _is_off_hours(ts: float | None) -> bool:
    try:
        if ts is None:
            return False
        hour = datetime.fromtimestamp(float(ts), tz=timezone.utc).hour
        return (hour < 6) or (hour >= 20)
    except Exception:
        return False


@register_rule(name='powershell_amsi_bypass_enriched', mitre=['T1059.001'], factors_required=['command_line','timestamp'], window_seconds=1200, severity='high', confidence_boost=0.5)
def amsi_bypass_enriched(event: Dict[str, Any]) -> bool:
    cmd = str(event.get('command_line') or '')
    if not cmd:
        return False
    lower = cmd.lower()
    if 'powershell' not in lower and 'pwsh' not in lower:
        return False

    matches = any(p.search(cmd) for p in _AMSI_PATTERNS)
    if not matches:
        return False

    score = 0.6
    # Off-hours boost
    if _is_off_hours(event.get('timestamp')):
        score += 0.1
    # If encoded command also present, raise score
    if ('-enc' in lower) or ('-encodedcommand' in lower):
        score += 0.1

    score = min(score, 0.95)
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'powershell_amsi_bypass_enriched',
            'mitre': ['T1059.001'],
            'computed_score': round(score, 3),
            'evidence': {'has_encoded': ('-enc' in lower) or ('-encodedcommand' in lower)},
        })
    except Exception:
        pass

    return score >= 0.65


__all__ = ["amsi_bypass_enriched"]
