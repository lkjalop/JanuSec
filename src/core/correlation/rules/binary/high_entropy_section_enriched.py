from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='high_entropy_section_enriched', mitre=['T1027'], factors_required=['binary_entropy'], window_seconds=86400, severity='medium', confidence_boost=0.3)
def high_entropy_section_enriched(event: Dict[str, Any]) -> bool:
    ent = event.get('binary_entropy') or 0.0
    score = 0.0
    try:
        if float(ent) > 7.5:
            score += 0.5
        elif float(ent) > 6.5:
            score += 0.25
    except Exception:
        pass
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'high_entropy_section_enriched','mitre':['T1027'],'computed_score':round(min(score,0.99),3),'evidence':{'entropy':ent}})
    except Exception:
        pass
    return score >= 0.45
