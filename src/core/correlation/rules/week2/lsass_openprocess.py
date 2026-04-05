from __future__ import annotations

from typing import Dict, Any
from ..registry import register_rule


# DUPLICATE_DISABLED decorator for rule cred_lsass_openprocess in src\core\correlation\rules\week2\lsass_openprocess.py
@register_rule(name='cred_lsass_openprocess', mitre=['T1003'], factors_required=['process','target'], window_seconds=3600, severity='critical', confidence_boost=0.6)
def cred_lsass_openprocess(event: Dict[str, Any]) -> bool:
    target = str(event.get('target') or '').lower()
    proc = str(event.get('process') or '').lower()
    if 'lsass' in target and proc not in ('system','lsass'):
        return True
    return False


@register_rule(name='corr_lsass_openprocess', mitre=['T1003','T1055'], factors_required=['process','target_process'], window_seconds=300, severity='high', confidence_boost=0.5)
def lsass_openprocess(event: Dict[str, Any]) -> bool:
    try:
        proc = str(event.get('process') or event.get('caller_process') or '').lower()
        target = str(event.get('target_process') or '').lower()
        if 'lsass' in target:
            # suspicious if unrelated process accesses lsass
            if proc and not any(x in proc for x in ('lsass','services','svchost')):
                return True
    except Exception:
        return False
    return False
