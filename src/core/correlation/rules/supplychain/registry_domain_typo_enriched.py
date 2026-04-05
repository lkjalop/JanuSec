from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='registry_domain_typo_enriched', mitre=['T1195'], factors_required=['package_source'], window_seconds=86400, severity='medium', confidence_boost=0.3)
def registry_domain_typo_enriched(event: Dict[str, Any]) -> bool:
    src = (event.get('package_source') or '').lower()
    score = 0.0
    if src and ('.om' in src or '.co' in src and 'pypi' not in src):
        score += 0.45
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'registry_domain_typo_enriched','mitre':['T1195'],'computed_score':round(min(score,0.99),3),'evidence':{'source':src}})
    except Exception:
        pass
    return score >= 0.45
