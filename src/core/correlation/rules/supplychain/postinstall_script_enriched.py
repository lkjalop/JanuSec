from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='postinstall_script_enriched', mitre=['T1195.002'], factors_required=['package_install_scripts','install_timestamp'], window_seconds=86400, severity='medium', confidence_boost=0.25)
def postinstall_script_enriched(event: Dict[str, Any]) -> bool:
    scripts = event.get('package_install_scripts') or []
    ts = event.get('install_timestamp')
    score = 0.0
    if scripts:
        # non-empty postinstall scripts suspicious
        score += 0.45
    # unusual install time (overnight) increases score
    try:
        if ts and (int(ts) % 86400) < 6*3600:
            score += 0.15
    except Exception:
        pass
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'postinstall_script_enriched','mitre':['T1195.002'],'computed_score':round(min(score,0.99),3),'evidence':{'scripts_count':len(scripts),'install_ts':ts}})
    except Exception:
        pass
    return score >= 0.5
