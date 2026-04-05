from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule

_TENANT_WHITELIST = {
    'tenant-a': {'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'},
}


@register_rule(name='tenant_artifact_whitelist_enriched', mitre=[], factors_required=['tenant_id','file_hash'], window_seconds=86400, severity='low', confidence_boost=-0.5)
def tenant_artifact_whitelist_enriched(event: Dict[str, Any]) -> bool:
    tenant = (event.get('tenant_id') or '').lower()
    fh = (event.get('file_hash') or '').lower()
    score = 0.0
    if tenant and fh and fh in _TENANT_WHITELIST.get(tenant, set()):
        score -= 0.8
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'tenant_artifact_whitelist_enriched','mitre':[],'computed_score':round(min(max(score,-1.0),0.99),3),'evidence':{'tenant':tenant,'hash':fh}})
    except Exception:
        pass
    return score < 0
