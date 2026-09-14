from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule
import os


@register_rule(name='signed_in_temp_enriched', mitre=['T1036'], factors_required=['file_signer','file_path'], window_seconds=86400, severity='medium', confidence_boost=0.2)
def signed_in_temp_enriched(event: Dict[str, Any]) -> bool:
    signer = (event.get('file_signer') or '').lower()
    path = (event.get('file_path') or '').lower()
    score = 0.0
    if signer and ('temp' in path or os.path.basename(path).startswith('tmp')):
        score += 0.45
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'signed_in_temp_enriched','mitre':['T1036'],'computed_score':round(min(score,0.99),3),'evidence':{'signer':signer,'path':path}})
    except Exception:
        pass
    return score >= 0.45
