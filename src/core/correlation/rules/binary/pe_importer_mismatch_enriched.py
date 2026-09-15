from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='pe_importer_mismatch_enriched', mitre=['T1055'], factors_required=['file_imports','file_signer'], window_seconds=86400, severity='medium', confidence_boost=0.2)
def pe_importer_mismatch_enriched(event: Dict[str, Any]) -> bool:
    imports = event.get('file_imports') or []
    signer = (event.get('file_signer') or '').lower()
    score = 0.0
    if signer and 'microsoft' not in signer and any('ntdll' in i.lower() for i in imports):
        score += 0.35
    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({'rule':'pe_importer_mismatch_enriched','mitre':['T1055'],'computed_score':round(min(score,0.99),3),'evidence':{'signer':signer,'imports_sample':imports[:5]}})
    except Exception:
        pass
    return score >= 0.4
