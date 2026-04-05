from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='macos_lolbin_enriched', mitre=['T1546.013'], factors_required=['process_name','cmdline','user'], window_seconds=3600, severity='medium', confidence_boost=0.2)
def macos_lolbin_enriched(event: Dict[str, Any]) -> bool:
    proc = (event.get('process_name') or '').lower()
    cmd = (event.get('cmdline') or '').lower()
    score = 0.0

    if proc in ('osascript', 'osascript.bin', 'osascript.app'):
        score += 0.4
    if 'osascript -e' in cmd or 'osascript /' in cmd:
        score += 0.25
    if 'launchctl' in proc or 'launchctl' in cmd:
        score += 0.25

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'macos_lolbin_enriched',
            'mitre': ['T1546.013'],
            'computed_score': round(min(score, 0.99), 3),
            'evidence': {'proc': proc, 'cmd': cmd},
        })
    except Exception:
        pass

    return score >= 0.5
