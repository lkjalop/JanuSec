from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='suspicious_unsigned_binary_enriched', mitre=['T1218'], factors_required=['file_signer','file_hash'], window_seconds=86400, severity='high', confidence_boost=0.4)
def suspicious_unsigned_binary_enriched(event: Dict[str, Any]) -> bool:
    signer = (event.get('file_signer') or '').lower()
    fh = (event.get('file_hash') or '').lower()
    score = 0.0
    if not signer:
        score += 0.5
    # rare known-bad hashes can be matched downstream; placeholder boost
    if fh and fh.startswith('deadbeef'):
        score += 0.45
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'suspicious_unsigned_binary_enriched','mitre':['T1218'],'computed_score':round(min(score,0.99),3),'evidence':{'signer':signer,'hash':fh}})
    except Exception:
        pass
    return score >= 0.55
