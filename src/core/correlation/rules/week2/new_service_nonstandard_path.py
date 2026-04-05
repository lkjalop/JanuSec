"""Placeholder rule: new_service_nonstandard_path
"""
from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule

@register_rule(name='corr_new_service_nonstandard_path', mitre=['T1543'], factors_required=['binary_path'], window_seconds=3600, severity='high', confidence_boost=0.4)
def new_service_nonstandard(event: Dict[str, Any]) -> bool:
    path = str(event.get('binary_path') or '').lower()
    if not path:
        return False
    # heuristic: service binary in temp, user profile, tools, downloads, or non-standard drive folders
    if ('\\temp\\' in path) or ('\\users\\' in path and '\\appdata\\' in path):
        return True
    if '\\tools\\' in path or '\\downloads\\' in path:
        return True
    # flag if not under typical system dirs (Program Files / Windows)
    if not any(x in path for x in ('\\program files\\', '\\program files (x86)\\', '\\windows\\', '\\system32\\')):
        # conservative: require path to be absolute and include a drive letter
        if len(path) > 3 and path[1:3] == ':\\':
            return True
    return False

__all__ = ["new_service_nonstandard"]
