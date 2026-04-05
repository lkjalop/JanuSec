from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='linux_lolbin_enriched', mitre=['T1546.004'], factors_required=['process_name','cmdline','uid'], window_seconds=3600, severity='medium', confidence_boost=0.2)
def linux_lolbin_enriched(event: Dict[str, Any]) -> bool:
    proc = (event.get('process_name') or '').lower()
    cmd = (event.get('cmdline') or '').lower()
    uid = event.get('uid')
    score = 0.0

    if proc in ('cron', 'crond') or 'cron' in cmd:
        score += 0.25
        if uid is not None and uid != 0:
            score += 0.25
    if 'nohup' in cmd or 'disown' in cmd:
        score += 0.25
    if 'systemd-run' in cmd or 'at ' in cmd:
        score += 0.25
    if 'sudo -u' in cmd and uid and uid != 0:
        score += 0.2

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'linux_lolbin_enriched',
            'mitre': ['T1546.004'],
            'computed_score': round(min(score, 0.99), 3),
            'evidence': {'proc': proc, 'cmd': cmd, 'uid': uid},
        })
    except Exception:
        pass

    return score >= 0.45
