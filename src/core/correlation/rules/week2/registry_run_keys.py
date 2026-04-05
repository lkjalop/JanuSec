"""Placeholder rule: registry_run_keys
"""
from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='corr_registry_run_keys', mitre=['T1547.001'], factors_required=['registry_key','process'], window_seconds=3600, severity='high', confidence_boost=0.35)
def registry_run_key(event: Dict[str, Any]) -> bool:
    try:
        key = str(event.get('registry_key') or '').lower()
        if not key:
            return False
        # common autorun locations
        if any(k in key for k in ('\\software\\microsoft\\windows\\currentversion\\run', 'runonce')):
            return True
    except Exception:
        pass
    return False

__all__ = ["registry_run_key"]
