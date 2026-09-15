from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule

_ALLOWED_TENANTS = {'internal-ops', 'security-team'}


@register_rule(name='tenant_allowance_enriched', mitre=[], factors_required=['tenant_id'], window_seconds=3600, severity='low', confidence_boost=-0.3)
def tenant_allowance_enriched(event: Dict[str, Any]) -> bool:
    tenant = (event.get('tenant_id') or '').lower()
    score = 0.0
    if tenant in _ALLOWED_TENANTS:
        score -= 0.6
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'tenant_allowance_enriched','mitre':[],'computed_score':round(min(max(score,-1.0),0.99),3),'evidence':{'tenant':tenant}})
    except Exception:
        pass
    return score < 0
