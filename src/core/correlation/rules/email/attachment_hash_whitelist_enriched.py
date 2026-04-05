from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule

# Simple in-memory whitelist for demo — in prod replace with DB/kv lookup
_WHITELIST = {'0123456789abcdef'}


@register_rule(name='attachment_hash_whitelist_enriched', mitre=['T1204.002'], factors_required=['attachments'], window_seconds=86400, severity='low', confidence_boost=-0.2)
def attachment_hash_whitelist_enriched(event: Dict[str, Any]) -> bool:
    attachments = event.get('attachments') or []
    score = 0.0
    for a in attachments:
        h = (a.get('sha256') or '').lower()
        if h and h in _WHITELIST:
            score -= 0.6
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'attachment_hash_whitelist_enriched','mitre':['T1204.002'],'computed_score':round(min(max(score,-1.0),0.99),3),'evidence':{'attachment_count':len(attachments)}})
    except Exception:
        pass
    return score < 0
