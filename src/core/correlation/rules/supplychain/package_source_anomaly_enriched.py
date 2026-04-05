from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='package_source_anomaly_enriched', mitre=['T1195'], factors_required=['package_name','package_source','package_version'], window_seconds=86400, severity='medium', confidence_boost=0.25)
def package_source_anomaly_enriched(event: Dict[str, Any]) -> bool:
    src = (event.get('package_source') or '').lower()
    ver = (event.get('package_version') or '').lower()
    score = 0.0
    if src and ('internal' not in src) and ('pypi' not in src) and not src.startswith('https://trusted.registry'):
        score += 0.4
    # weird versioning scheme can boost
    if ver and any(c.isalpha() for c in ver):
        score += 0.2
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'package_source_anomaly_enriched','mitre':['T1195'],'computed_score':round(min(score,0.99),3),'evidence':{'source':src,'version':ver}})
    except Exception:
        pass
    return score >= 0.5
